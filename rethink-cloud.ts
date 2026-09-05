import express from 'express'
import stripJsonComments from 'strip-json-comments'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import * as https from 'node:https'
import { spawnSync } from 'node:child_process'
import { dirname, resolve, join } from 'node:path'
import { tmpdir } from 'node:os'
import { Broker } from './cloud/mqtt-broker'
import * as tls from 'node:tls'
import * as net from 'node:net'
import { X509Certificate } from 'node:crypto'
import { routes as thinq1Routes } from './cloud/thinq1/http'
import { routes as thinq2Routes } from './cloud/thinq2/provisioning'
import { DeviceAcceptor as T1Acceptor } from './cloud/thinq1/device'
import { DeviceAcceptor as T2Acceptor } from './cloud/thinq2/device'
import { Connection as HA_connection } from './cloud/homeassistant'
import HA_bridge from './cloud/ha_bridge'
import { normalize as normalizeConfig, RawConfig, CA } from './util/config'
import * as Management from './management'

import log, { setFilter as setLogFilter } from './util/logging'
import { DeviceManager } from './cloud/devmgr'
import { Bridge } from './bridge'
import { JSONStorage } from './bridge/state'

const configPath = resolve(process.argv[2] ?? './config.json')
const configDir = dirname(configPath)
const config = normalizeConfig(JSON.parse(stripJsonComments(readFileSync(configPath).toString('utf-8'))) as RawConfig)

config.ca_key_file = resolve(configDir, config.ca_key_file)
config.ca_cert_file = resolve(configDir, config.ca_cert_file)
if (config.bridge) config.bridge.storage_path = resolve(configDir, config.bridge.storage_path)

if (!config.log) config.log = ['status', 'incoming', 'HTTPS']

const enabled = Object.fromEntries(config.log.map((key) => [key, true]))
setLogFilter((topic) => {
    return enabled[topic] || enabled['all']
})

// if you add spaces here, you will have to fix quoting in the code below
// the CA is also the server
function loadOrCreateCert(): CA {
    let keypem: string, certpem: string
    try {
        keypem = readFileSync(config.ca_key_file).toString('utf-8')
        certpem = readFileSync(config.ca_cert_file).toString('utf-8')

        if (!new X509Certificate(certpem).checkHost(config.hostname))
            throw new Error('invalid subject, creating new certificate')
    } catch (err) {
        log('status', 'Creating a new key/certificate for the CA')
        spawnSync('openssl', [
            'req',
            '-x509',
            '-newkey',
            'rsa:4096',
            '-keyout',
            config.ca_key_file,
            '-out',
            config.ca_cert_file,
            '-sha256',
            '-days',
            '3650',
            '-nodes',
            '-subj',
            '/CN=' + config.hostname,
        ])
        keypem = readFileSync(config.ca_key_file).toString('utf-8')
        certpem = readFileSync(config.ca_cert_file).toString('utf-8')
    }

    return { key: keypem, cert: certpem }
}

const ca = loadOrCreateCert()

// Real LG AC units of the same modelId can each demand a different SNI hostname when
// connecting to the MQTTS port (e.g. `kic-common.lgthinq.com` on one unit, `kic-mclip.lgthinq.com`
// on another). rethink only ever presents one certificate, issued for `config.hostname`, via
// `SNICallback` being unset (Node falls back to the options passed to tls.createServer/https.createServer
// for every connection regardless of the requested name). The HTTPS provisioning port (443) doesn't
// validate the server cert so any single name slips through there, but the MQTTS port (8885) does
// validate it, so a unit asking for a name that doesn't match `config.hostname` fails to connect.
//
// To fix that, every server below gets a SNICallback that mints a leaf certificate on demand for
// whatever name was requested, signed by our own CA (the same CA whose public cert is already
// handed to devices at GET /route/certificate, so anything it signs is trusted). Certificates are
// cached per servername so we only shell out to openssl once per distinct SNI name.
//
// Implementation note (openssl 3 pitfalls): `openssl x509 -req -CA <cert> -key <key>` silently
// ignores `-key` and signs with an ephemeral key instead of the CA's -- the correct flag to sign
// with the CA's private key is `-CAkey`, not `-key` (that's reserved for signing the *new* leaf
// key request, which we don't need here since we generate the CSR with its own key first). We also
// avoid piping the generated key/cert through /dev/stdout (which fails when stdout is a pipe, as it
// is when spawned from Node) by writing everything to a scratch directory instead.
const sniContextCache = new Map<string, tls.SecureContext>()

function issueLeafCertificate(servername: string): { key: string; cert: string } {
    const dir = mkdtempSync(join(tmpdir(), 'rethink-sni-'))
    try {
        const caKeyPath = join(dir, 'ca.key')
        const caCertPath = join(dir, 'ca.crt')
        const leafKeyPath = join(dir, 'leaf.key')
        const leafCsrPath = join(dir, 'leaf.csr')
        const leafCertPath = join(dir, 'leaf.crt')

        writeFileSync(caKeyPath, ca.key)
        writeFileSync(caCertPath, ca.cert)

        // 1. generate a fresh keypair + CSR for this SNI name
        spawnSync('openssl', [
            'req',
            '-new',
            '-newkey',
            'rsa:2048',
            '-nodes',
            '-keyout',
            leafKeyPath,
            '-out',
            leafCsrPath,
            '-subj',
            '/CN=' + servername,
        ])

        // 2. sign the CSR with our CA (-CAkey, NOT -key, or openssl 3 ignores the CA's key)
        spawnSync('openssl', [
            'x509',
            '-req',
            '-in',
            leafCsrPath,
            '-CA',
            caCertPath,
            '-CAkey',
            caKeyPath,
            '-CAcreateserial',
            '-out',
            leafCertPath,
            '-days',
            '3650',
            '-sha256',
        ])

        return {
            key: readFileSync(leafKeyPath, 'utf-8'),
            cert: readFileSync(leafCertPath, 'utf-8'),
        }
    } finally {
        rmSync(dir, { recursive: true, force: true })
    }
}

function sniCallback(servername: string, cb: (err: Error | null, ctx?: tls.SecureContext) => void) {
    try {
        let ctx = sniContextCache.get(servername)
        if (!ctx) {
            const leaf = issueLeafCertificate(servername)
            ctx = tls.createSecureContext({ key: leaf.key, cert: leaf.cert + '\n' + ca.cert })
            sniContextCache.set(servername, ctx)
            log('status', `Issued SNI certificate for ${servername}`)
        }
        cb(null, ctx)
    } catch (err) {
        log('status', `Failed to issue SNI certificate for ${servername}: ${err}`)
        cb(err as Error)
    }
}

// Default TLS options for every server below: fall back to the config.hostname cert for
// non-SNI clients, but let SNICallback override with a per-name cert whenever one is requested.
const tlsOptions = { ...ca, SNICallback: sniCallback }

// Thinq1
function t1setup(manager: DeviceManager) {
    // Thinq1 HTTPS server
    const app = express()
    app.use(function (req, res, next) {
        log('HTTPS', req.hostname, req.url)
        next()
    })

    app.use(thinq1Routes(config))

    // fallback
    app.use((req, res) => {
        res.json({})
    })

    https.createServer(tlsOptions, app).listen(config.thinq1_https_port.bind, config.thinq1_https_port.address)
    const acceptor = new T1Acceptor()
    tls.createServer(tlsOptions, acceptor.accept.bind(acceptor)).listen(
        config.thinq1_port.bind,
        config.thinq1_port.address,
    )
    acceptor.on('newDevice', manager.accept.bind(manager))
}

// Thinq2
function t2setup(manager: DeviceManager) {
    // Thinq2 HTTPS server
    const app = express()
    app.use(express.json())

    app.use(function (req, res, next) {
        log('HTTPS', req.hostname, req.url)
        next()
    })

    app.use(thinq2Routes(config, ca))

    // fallback
    app.use((req, res) => {
        res.header('content-type', 'text/xml;charset=utf-8')
        res.end('')
    })

    https.createServer(tlsOptions, app).listen(config.https_port.bind, config.https_port.address)

    // internal MQTT broker
    const broker = new Broker()

    if (config.mqtt) {
        tls.createServer(tlsOptions, broker.accept.bind(broker)).listen(
            config.mqtts_port.bind,
            config.mqtts_port.address,
        )
        net.createServer({}, broker.accept.bind(broker)).listen(config.mqtt_port.bind, config.mqtt_port.address)
    }

    const acceptor = new T2Acceptor(broker)
    acceptor.on('newDevice', manager.accept.bind(manager))
}

// HA connector
const ha = new HA_bridge(new HA_connection(config.homeassistant))
const manager = new DeviceManager()
manager.on('newDevice', (dev) => ha.newDevice(dev))

t1setup(manager)
t2setup(manager)

let bridge: Bridge | undefined
if (config.bridge) {
    mkdirSync(config.bridge.storage_path, { recursive: true })
    const storage = new JSONStorage(config.bridge.storage_path)
    bridge = new Bridge(storage, manager)
}

if (config.management_port)
    Management.app(ha, manager, bridge).listen(config.management_port.bind, config.management_port.address)

console.log('Rethink cloud ready')

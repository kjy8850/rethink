import { createHash, publicEncrypt, randomBytes } from 'node:crypto'
import * as OAuth2 from './oauth2'
import { RSA_PKCS1_PADDING } from 'node:constants'
import { generateKeyAndCsr } from '@/util/pki'
import fetch, { type RequestInit } from 'node-fetch'
import { Metadata } from '@/cloud/thinq'

export const IOT_BASE_URL = 'https://common.lgthinq.com'
const GATEWAY_URL = 'https://route.lgthinq.com:46030/v1/service/application/gateway-uri'

export function signInUrl(baseUrl: string, countryCode: string) {
    const url = new URL(baseUrl + 'signin')
    url.searchParams.set('callback_url', 'https://kr.m.lgaccount.com/login/iabClose')
    url.searchParams.set('redirect_url', 'https://kr.m.lgaccount.com/login/iabClose')
    url.searchParams.set('client_id', 'LGAO221A02')
    url.searchParams.set('country', countryCode)
    url.searchParams.set('language', 'en')
    url.searchParams.set('svc_integrated', 'Y')
    url.searchParams.set('state', 'signin')
    url.searchParams.set('svc_code', 'SVC202')
    return url
}

export async function apiFetch<T = unknown>(url: string, options: RequestInit): Promise<T> {
    let out: { resultCode: string; result: T }
    for (let i = 0; ; i++) {
        try {
            const resp = await fetch(url, {
                ...options,
                headers: {
                    ...(options.headers ?? {}),
                    'x-message-id': randomBytes(16).toString('hex'),
                },
            })
            out = (await resp.json()) as { resultCode: string; result: T }
            break
        } catch (err) {
            if (i >= 3) throw err
            await new Promise((resolve) => setTimeout(resolve, 1000))
        }
    }

    if (out.resultCode !== '0000') {
        console.log(url, options, out)
        throw new RemoteError(url, out.resultCode, out.result)
    }

    return out.result
}

export class RemoteError extends Error {
    constructor(
        readonly url: string,
        readonly resultCode: string,
        readonly result: unknown,
    ) {
        super(ErrorStrings[resultCode] ?? `Unknown thinq error ${resultCode}`)
    }
}

type GatewayResponse = {
    rtiUri: string
    thinq1Uri: string
    thinq2Uri: string
    uris: {
        empOauthBaseUri: string
        empFrontBaseUri2: string
    }
}

type ProfileResponse = {
    status: number
    account: {
        userID: string
        userNo: string
    }
}

type HomesResponse = {
    item: {
        homeId: string
        currentHomeYn: 'Y' | 'N'
    }[]
}

type HomeResponse = {
    homeId: string
    devices: {
        deviceId: string
        deviceType: number
        modelName: string
        alias: string
        snapshot: unknown
        online: boolean
    }[]
}

type OtpResponse = { otp: string; publicKey: string }

type ModelJsonResponse = {
    modelJsonUri: string
    modelJsonVer?: string
}

export type Environment = {
    countryCode: string
}

/*
 * The nested appliance in a combined-product registration, mirroring the ThinQ app's
 * com.lgeha.nuts.registration.model.SubDevice: aliasPrefix, ciphertext, deviceId, deviceType,
 * modelName, modemVer, regIndex.
 */
/*
 * Field types follow the app's class exactly: regIndex is a String there, not a number, and
 * RegisterDeviceRequestBody.subDevice is a List, not a single object. Sending an object where
 * a list belongs, or a number where a string belongs, is enough for the cloud to fail
 * deserialization and answer with a bare '9999' and an empty body.
 */
export type SubDeviceRegistration = {
    deviceId: string
    deviceType: string
    modelName: string
    aliasPrefix: string
    ciphertext: string
    regIndex: string
    modemVer?: string
}

/*
 * The fields beyond the eight rethink has always sent that the ThinQ app also fills in. A
 * single appliance registers without them; a combined product answered '0005' without a
 * subDevice and then '9999' with one, so the rest of the app's body is the next thing to
 * match. Every value here is read back from the cloud's own record of the appliance rather
 * than invented, so nothing is asserted that the account does not already hold.
 */
export type RegistrationExtras = {
    deviceCode?: string
    modemVer?: string
    ssid?: string
    timezoneCode?: string
    regIndex?: string
    salesModelName?: string
    serialNo?: string
    demandType?: string
    networkType?: string
    subModelNm?: string
}

export class Client {
    headers: Record<string, string> = {
        'content-type': 'application/json;charset=UTF-8',
        accept: 'application/json',
        'x-thinq-app-ver': '4.1.5000',
        'x-thinq-app-type': 'NUTS',
        'x-thinq-app-level': 'PRD',
        'x-thinq-app-os': 'ANDROID',
        'x-service-code': 'SVC202',
        // x-country-code
        // x-language-code
        'x-service-phase': 'OP',
        'x-origin': 'app-web-ANDROID',
        'x-thinq-app-logintype': 'LGE',
        // x-user-no
        // x-emp-token
        'x-api-key': 'VGhpblEyLjAgU0VSVklDRQ==',
    }

    static gatewayCache: Record<string, Promise<GatewayResponse>> = {}
    gateway: Promise<GatewayResponse>
    homeId: string | undefined
    clientId: string

    constructor(
        readonly env: Environment,
        client_id?: string,
    ) {
        this.headers['x-country-code'] = env.countryCode
        this.headers['x-language-code'] = 'en-' + env.countryCode
        if (!client_id) client_id = randomBytes(32).toString('hex')

        this.clientId = this.headers['x-client-id'] = client_id

        if (Client.gatewayCache[env.countryCode] !== undefined) this.gateway = Client.gatewayCache[env.countryCode]
        else
            Client.gatewayCache[env.countryCode] = this.gateway = apiFetch<GatewayResponse>(GATEWAY_URL, {
                headers: this.headers,
            })
    }

    async getUrls() {
        const gw = await this.gateway
        return {
            webUrl: gw.uris.empFrontBaseUri2,
            authUrl: gw.uris.empOauthBaseUri,
        }
    }

    async auth(refreshToken: string) {
        const {
            thinq2Uri,
            uris: { empOauthBaseUri: authUrl },
        } = await this.gateway
        const { accessToken } = await OAuth2.refresh(authUrl, refreshToken)

        const profile = await OAuth2.signedRequest<ProfileResponse>(authUrl + '/users/profile', {
            Authorization: `Bearer ${accessToken}`,
            'X-Device-Type': 'M01',
            'X-Device-Platform': 'ADR',
        })

        if (profile.status !== 1) {
            console.log(profile)
            throw new Error("Can't query user information")
        }

        console.log(`Welcome ${profile.account.userID}!`)

        this.headers['x-user-no'] = profile.account.userNo
        this.headers['x-emp-token'] = accessToken

        // I'm not sure what this call means, but without it, the otp/certificate call returns "access denied"
        await apiFetch(`${thinq2Uri}/service/users/client`, {
            headers: { ...this.headers, 'x-device-type': '601' },
            method: 'POST',
        })

        const { item: homes } = await apiFetch<HomesResponse>(`${thinq2Uri}/service/homes`, { headers: this.headers })
        for (const home of homes) {
            if (home.currentHomeYn === 'Y') this.homeId = home.homeId
        }
    }

    async listDevices() {
        if (!this.homeId) throw new Error('Current home is not set')

        const { thinq2Uri } = await this.gateway
        const home = await apiFetch<HomeResponse>(`${thinq2Uri}/service/homes/${this.homeId}`, {
            headers: this.headers,
        })
        return home.devices
    }

    /*
     * The whole home record, not just the deviceId/alias pair listDevices() keeps.
     *
     * addDevice() is refused with an undocumented '0005' and an empty body for both halves of a
     * WashTower, so there is nothing in the failure itself to read. What the cloud already stores
     * about those two appliances is the next best thing: if the pair is modelled as a group, the
     * shape of it shows up here. Read-only.
     */
    async getHome() {
        if (!this.homeId) throw new Error('Current home is not set')

        const { thinq2Uri } = await this.gateway
        return await apiFetch<unknown>(`${thinq2Uri}/service/homes/${this.homeId}`, { headers: this.headers })
    }

    /*
     * GET any path under thinq2Uri. Read-only by construction: no method other than GET is issued.
     *
     * The ThinQ app addresses a much larger API than rethink models -- among it
     * service/homes/{homeId}/group-types, service/groups and
     * service/homes/{homeId}/devices/{groupType}. A WashTower is stored as a group of
     * type "kepler", and addDevice() (which posts a single appliance to
     * service/homes/{homeId}/devices) is refused for it, so the group endpoints are where an
     * answer would be. This exists to read them without a release per URL.
     */
    async getAny(path: string) {
        return await this.callAny('GET', path)
    }

    /*
     * Issue one request against thinq2Uri with a body of the caller's choosing.
     *
     * Working out what the cloud wants for a combined product is a matter of trying a request,
     * reading the code it comes back with, and adjusting -- which is not worth a release per
     * attempt. This is a debugging tool: it can reach destructive endpoints (devices/delete
     * among them), so the caller is responsible for what it sends.
     */
    async callAny(method: string, path: string, body?: unknown) {
        if (/:\/\/|\.\./.test(path)) throw new Error('Path must stay under the ThinQ service root')

        const { thinq2Uri } = await this.gateway
        const clean = path.replace(/^\/+/, '').replace('{homeId}', this.homeId ?? '')
        return await apiFetch<unknown>(`${thinq2Uri}/${clean}`, {
            headers: this.headers,
            method,
            ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        })
    }

    async removeDevice(deviceId: string) {
        if (!this.homeId) throw new Error('Current home is not set')

        const { thinq2Uri } = await this.gateway
        try {
            await apiFetch(`${thinq2Uri}/service/homes/${this.homeId}/devices/delete`, {
                headers: this.headers,
                method: 'POST',
                body: JSON.stringify({
                    homeId: this.homeId,
                    item: [{ deviceId }],
                }),
            })
        } catch (err) {
            if (err instanceof RemoteError && err.resultCode === ErrorCodes.ERROR_NO_REGISTERED_DEVICES) return // no such device

            throw err
        }
    }

    async prepareNewT2Device() {
        const { thinq2Uri } = await this.gateway
        return await apiFetch<OtpResponse>(`${thinq2Uri}/service/devices/otp/certificate`, {
            headers: this.headers,
            body: '{}',
            method: 'POST',
        })
    }

    // An appliance that is already registered in this home is left alone. Re-registering it would
    // need initDevice=true, which makes the cloud drop the registration and build a new one: the
    // appliance disappears from the owner's app, gets re-announced under a new name, and can no
    // longer reach LG on its own. Bridging does not need a fresh registration - the credentials
    // come from pair(), which has already run by this point.
    // ciphertext is required for Thinq2 devices
    async addDevice(
        device: Device,
        alias: string,
        deviceType: string,
        ciphertext?: Buffer,
        subDevice?: SubDeviceRegistration,
        extras?: RegistrationExtras,
    ) {
        if (!this.homeId) throw new Error('Current home is not set')

        const { thinq2Uri } = await this.gateway
        const body = {
            deviceId: device.deviceId,
            countryCode: this.env.countryCode,
            deviceType,
            modelName: device.meta.modelName,
            aliasPrefix: alias,
            platformType: device.platformType,
            ciphertext: ciphertext ? ciphertext.toString('base64') : undefined,
            initDevice: false,
            /*
             * A combined product -- a WashTower, which the cloud stores as a group of type
             * "kepler" -- is registered as one appliance carrying the other, not as two
             * appliances. The ThinQ app's RegisterDeviceRequestBody has a subDevice field of
             * type SubDevice for exactly this, and its code branches on "subDevice mandatory".
             * Registering either half on its own is what the cloud refuses with the
             * undocumented '0005' (anszom/rethink#79).
             */
            ...(subDevice ? { subDevice: [subDevice] } : {}),
            ...(extras ?? {}),
        }

        try {
            await apiFetch(`${thinq2Uri}/service/homes/${this.homeId}/devices`, {
                headers: this.headers,
                method: 'POST',
                body: JSON.stringify(body),
            })
        } catch (err) {
            // '0005' is undocumented (not in ErrorCodes) and a WashTower pair answers with it on
            // every addDevice. A community report reads it as "already registered", the cloud
            // having linked washer and dryer as one 1+1 group when the first unit was added
            // (https://github.com/anszom/rethink/issues/79#issuecomment-5299814720), and bridging
            // does work from the credentials pair() already issued -- so this is not fatal.
            //
            // It is not proof of registration either: seen here on a pair that modelJSON and the
            // ThinQ app both reported as absent from the home. Say what happened rather than
            // reporting success, so a bridge that is up but unregistered is not mistaken for a
            // finished registration.
            if (err instanceof RemoteError && err.resultCode === '0005') {
                console.log(
                    `Registration of ${device.deviceId} refused with '0005' (paired-appliance group). ` +
                        'Bridging continues on the credentials from pair(); the home registration is unchanged.',
                )
                // '0005' is undocumented, so log whatever else the cloud sent back with it -- the
                // resultCode alone has not been enough to tell what it is objecting to.
                console.log(`  '0005' response body: ${JSON.stringify(err.result)}`)
                return
            }
            if (err instanceof RemoteError && err.resultCode === ErrorCodes.ERROR_ALREADY_DEVICES_REGISTERED_IN_HOME) {
                console.log('Device already registered, keeping the existing registration')
            } else {
                if (err instanceof RemoteError) {
                    // Say which code came back and what the body carried; a bare rethrow loses both,
                    // and these registrations fail with codes the ErrorCodes table does not explain.
                    console.log(
                        `addDevice for ${device.deviceId} failed with '${err.resultCode}' ` +
                            `(${ErrorStrings[err.resultCode] ?? 'unlisted'}): ${JSON.stringify(err.result)}`,
                    )
                    console.log(`  request body was: ${JSON.stringify(body)}`)
                }
                throw err
            }
        }
    }

    // The modelJSON describes the capabilities of a device model (field layouts, enum values,
    // course tables). The descriptor call requires a device registered in the current account,
    // but the URI it returns is a plain, time-limited link that needs no authentication.
    async getModelJson(deviceId: string, modelName: string) {
        const { thinq2Uri } = await this.gateway
        const url = new URL(`${thinq2Uri}/service/application/modeljson`)
        url.searchParams.set('deviceId', deviceId)
        url.searchParams.set('modelName', modelName)

        const { modelJsonUri } = await apiFetch<ModelJsonResponse>(url.toString(), { headers: this.headers })

        const resp = await fetch(modelJsonUri)
        if (!resp.ok) throw new Error(`Can't download the modelJSON: HTTP ${resp.status}`)

        return await resp.text()
    }

    async getDeviceStatus(deviceId: string) {
        const { thinq2Uri } = await this.gateway
        return await apiFetch(`${thinq2Uri}/service/devices/${deviceId}`, { headers: this.headers })
    }
}

export type RouteResponse = { apiServer: string; mqttServer: string }
export type RouteCertResponse = { certificatePem: string }

/**
 * The CA that signs the real cloud's AWS-IoT endpoint - the trust anchor for any MQTT connection we
 * make to LG, whether as a bridged appliance or as the monitor's own subscription.
 */
export async function fetchIotCaCertificate() {
    const { certificatePem } = await apiFetch<RouteCertResponse>(`${IOT_BASE_URL}/route/certificate?name=aws-iot`, {
        headers: { accept: 'application/json' },
    })
    return certificatePem
}
type CertResponse = {
    certificatePem: string
    publication: {
        message: string
        provisioning: string
        control: string
        service: {
            appliance: string
            appupdate: string
        }
    }
    subscription: {
        message: string
        service: {
            appliance: string
            appupdate: string
        }
    }
}

export type Device = {
    platformType: 'thinq1' | 'thinq2'
    deviceId: string
    meta: Metadata
}

export type Thinq1DeviceState = {
    rtiServer: string
    httpServer: string
}

export class Thinq1Device implements Device {
    readonly platformType = 'thinq1'
    constructor(
        readonly deviceId: string,
        readonly meta: Metadata,
        readonly state: Thinq1DeviceState,
    ) {}
}

export type Thinq2DeviceState = {
    countryCode: string
    apiServer: string
    mqttServer: string
    caCertificate: string
    privateKey: string
    certificate: string
    pubTopic: string
    provTopic: string
    subTopic: string
    // The device's real deploy appInfo/platformInfo, captured at registration. Forwarded
    // upstream in preDeploy so the cloud sees the true protocolVer/softVer/etc. Optional
    // because states registered before this was captured won't have it (re-register to fill).
    deployAppInfo?: Record<string, unknown>
    deployPlatformInfo?: Record<string, unknown>
}

export class Thinq2Device implements Device {
    readonly platformType = 'thinq2'
    nonce = randomBytes(8)
    state?: Thinq2DeviceState

    constructor(
        readonly deviceId: string,
        readonly meta: Metadata,
        state?: Thinq2DeviceState,
    ) {
        this.state = state
    }

    async pair(env: Environment, otpResponse: OtpResponse): Promise<Buffer> {
        console.log('Fetching API urls')
        const servers = (await Promise.race([
            apiFetch<RouteResponse>(`${IOT_BASE_URL}/route`, {
                headers: { 'x-country-code': env.countryCode, 'x-service-phase': 'OP', accept: 'application/json' },
            }),
            new Promise((resolve) => setTimeout(resolve, 5000)),
        ])) as RouteResponse | undefined

        if (!servers) {
            console.log(`Failed to fetch ${IOT_BASE_URL}, make sure that you are not redirecting this address!`)
            throw new Error(`route fetch failed on ${IOT_BASE_URL}`)
        }

        console.log('Fetching CA cert')
        const ca = await fetchIotCaCertificate()

        console.log('Trying to generate a certificate with otp', otpResponse.otp)

        const { privateKey, publicKey, csr } = generateKeyAndCsr('/CN=*.clip.com/O=LGE/C=KR', 'ec')

        const ciphertext = publicEncrypt(
            { key: otpResponse.publicKey, padding: RSA_PKCS1_PADDING },
            Buffer.concat([
                this.nonce,
                Buffer.from(otpResponse.otp, 'utf-8'),
                createHash('sha256').update(this.deviceId).digest(),
                createHash('sha256').update(csr).digest(),
                createHash('sha256').update(publicKey).digest(),
            ]),
        )

        const deviceConfig = await apiFetch<CertResponse>(`${servers.apiServer}/device/${this.deviceId}/certificate`, {
            method: 'POST',
            headers: { 'x-provide-type': 'immediate', 'Content-type': 'application/json' },
            body: JSON.stringify({
                otp: otpResponse.otp,
                csr: csr,
                publickey: publicKey,
                ciphertext: ciphertext.toString('base64'),
            }),
        })

        this.state = {
            ...servers,
            countryCode: env.countryCode,
            caCertificate: ca,
            privateKey,
            certificate: deviceConfig.certificatePem,
            pubTopic: deviceConfig.publication.message,
            provTopic: deviceConfig.publication.provisioning,
            subTopic: deviceConfig.subscription.message,
        }

        return publicEncrypt(
            { key: otpResponse.publicKey, padding: RSA_PKCS1_PADDING },
            Buffer.concat([this.nonce, createHash('sha256').update(this.deviceId).digest()]),
        )
    }
}

export const ErrorStrings: Record<string, string> = {
    '0000': 'SUCCESS_OK',
    '0004': 'ERROR_DUPLICATED_LOGIN',
    '0007': 'ERROR_NO_SERVICE',
    '0008': 'ERROR_EXIST_DUPLICATED_DATA',
    '0009': 'ERROR_NO_DEVICES',
    '0010': 'ERROR_NO_DATA',
    '0011': 'ERROR_NO_PERMISSIONS',
    '0101': 'ERROR_NO_REGISTERED_DEVICES', // or "ERROR_DELETED_PRODUCT",
    '0102': 'ERROR_FAILED_LOGIN',
    '0018': 'ERROR_ANOTHER_USER_IN_USE',
    '0110': 'ERROR_DISAGREED_TERMS',
    '0112': 'ERROR_MAXIMUM_ROOM',
    '0125': 'ERROR_ALREADY_DEVICES_REGISTERED_IN_HOME',
    '0128': 'ERROR_UPDATING_FOTA',
    '0129': 'ERROR_MANAGER_NO_PERMISSIONS',
    '9016': 'ERROR_DUPLICATED_REQUEST',
    '9995': 'ERROR_NO_INTERNET',
    '9996': 'ERROR_NO_DOCUMENT',
    '9997': 'ERROR_NO_COLLECTION',
    '9998': 'ERROR_NO_USER',
    '9999': 'ERROR_UNKNOWN',
}

export const ErrorCodes = {
    SUCCESS_OK: '0000',
    ERROR_DUPLICATED_LOGIN: '0004',
    ERROR_NO_SERVICE: '0007',
    ERROR_EXIST_DUPLICATED_DATA: '0008',
    ERROR_NO_DEVICES: '0009',
    ERROR_NO_DATA: '0010',
    ERROR_NO_PERMISSIONS: '0011',
    ERROR_NO_REGISTERED_DEVICES: '0101',
    ERROR_DELETED_PRODUCT: '0101',
    ERROR_FAILED_LOGIN: '0102',
    ERROR_ANOTHER_USER_IN_USE: '0018',
    ERROR_DISAGREED_TERMS: '0110',
    ERROR_MAXIMUM_ROOM: '0112',
    ERROR_ALREADY_DEVICES_REGISTERED_IN_HOME: '0125',
    ERROR_UPDATING_FOTA: '0128',
    ERROR_MANAGER_NO_PERMISSIONS: '0129',
    ERROR_DUPLICATED_REQUEST: '9016',
    ERROR_NO_INTERNET: '9995',
    ERROR_NO_DOCUMENT: '9996',
    ERROR_NO_COLLECTION: '9997',
    ERROR_NO_USER: '9998',
    ERROR_UNKNOWN: '9999',
}

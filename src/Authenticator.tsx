import ServerCookies from 'cookies';
import { IncomingMessage, ServerResponse } from 'http';
import { AntiCSRF } from './AntiCSRF';

// Client auth state
export type AuthClient<S> = { loggedin: true; state: S } | { loggedin: false; error?: any };

// Server auth state includes the payload (stored in httpOnly cookie)
export type AuthServer<P, S> =
    | { loggedin: true; payload: P; state: S }
    | { loggedin: false; error?: any };

export class Authenticator<P, S = P, CSRF extends AntiCSRF = AntiCSRF> {
    constructor(
        public decode: (token: string) => P | undefined,
        public extract: (payload: P) => S,
        public csrf?: CSRF,
    ) {}

    // Creates a sticky AuthSession using an httpOnly cookie (this protects the auth token from XSS
    // attacks). Being httpOnly the cookie is not readable from the client. Use the `extract`
    // callback to define client-visible state derived from the auth token
    setCookie(
        req: IncomingMessage,
        res: ServerResponse,
        payload: P,
        token: string,
    ): AuthServer<P, S> {
        const cookies = new ServerCookies(req, res);
        cookies.set('auth_token', token);
        return {
            loggedin: true,
            payload,
            state: this.extract(payload),
        };
    }

    // Remove stick AuthSession. Effectively logs the user out
    removeCookie(req: IncomingMessage, res: ServerResponse): void {
        const cookies = new ServerCookies(req, res);
        cookies.set('auth_token', null, { maxAge: 0 });
    }

    // Search for an anti-CSRF token on the request object, or optionally the (preparsed) request
    // body. Starts by checking for a `X-XSRF-TOKEN` header, then if the Content-Type is a form we
    // look for a hidden field (assuming the body is preparsed), and finally falling back to a
    // `_csrfToken` query paramter
    async getCSRF(
        req: IncomingMessage,
        body?: Record<string, any>,
    ): Promise<string | number | undefined> {
        const xsrfHeader = req.headers['x-xsrf-token'];
        if (xsrfHeader !== undefined) {
            if (typeof xsrfHeader !== 'string') {
                console.error('was expected a string');
                return 400;
            }
            return xsrfHeader;
        }

        const contentHeader = req.headers['content-type'];
        if (contentHeader === 'application/x-www-form-urlencoded' && body !== undefined) {
            const csrfToken = body._csrfToken;
            if (typeof csrfToken !== 'string') {
                console.error('was expected a string');
                return 400;
            }
            return csrfToken;
        }

        if (req.url === undefined) {
            return undefined;
        }

        const proto = req.headers.referer?.split(':')[0] ?? 'http';
        const url = new URL(req.url, `${proto}://${req.headers.host}/`);
        return url.searchParams.get('_csrfToken') ?? undefined;
    }

    // Verify that the request object (or body) has a valid anti-CSRF token
    async verifyCSRF(req: IncomingMessage, body?: Record<string, any>): Promise<number> {
        if (this.csrf === undefined) {
            throw Error('AntiCSRF instance not provided');
        }

        const csrfToken = await this.getCSRF(req, body);
        if (typeof csrfToken === 'number') {
            return csrfToken;
        } else if (csrfToken === undefined) {
            console.error('no anti-CSRF token present');
            return 400;
        } else if (!this.csrf.verify(csrfToken)) {
            console.error('failed to verify anti-CSRF token');
            return 401;
        }
        return 200;
    }

    // Read the auth session from the cookie (if there is one)
    async fromCookieWithoutCSRF(
        req: IncomingMessage,
        res: ServerResponse,
    ): Promise<AuthServer<P, S>> {
        const cookies = new ServerCookies(req, res);
        const encodedToken = cookies.get('auth_token');
        if (encodedToken === undefined) {
            return { loggedin: false, error: 'no auth token' };
        }

        const token = this.decode(encodedToken);
        if (token === undefined) {
            return { loggedin: false, error: 'failed to verify auth token' };
        }

        return {
            loggedin: true,
            payload: token,
            state: this.extract(token),
        };
    }

    // Same as `fromCookieWithoutCSRF`, but first checks for a valid anti-CSRF token on the request
    // object (or body)
    async fromCookie(
        req: IncomingMessage,
        res: ServerResponse,
        body?: Record<string, any>,
    ): Promise<AuthServer<P, S>> {
        const csrfStatus = await this.verifyCSRF(req, body);
        if (csrfStatus !== 200) {
            return {
                loggedin: false,
                error: 'failed to verify CSRF token',
            };
        }
        return this.fromCookieWithoutCSRF(req, res);
    }
}

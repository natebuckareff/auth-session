import ServerCookies from 'cookies';
import { IncomingMessage, ServerResponse } from 'http';
import { NextPage, NextPageContext } from 'next';
import React, { createContext, useContext } from 'react';

// Client auth state
export type AuthClient<S> = { loggedin: true; state: S } | { loggedin: false; error?: any };

// Server auth state includes the payload (stored in httpOnly cookie)
export type AuthServer<P, S> =
    | { loggedin: true; payload: P; state: S }
    | { loggedin: false; error?: any };

function authServerToClient<T, S>(authServer: AuthServer<T, S>): AuthClient<S> {
    if (authServer.loggedin) {
        return { loggedin: true, state: authServer.state };
    } else {
        return authServer;
    }
}

export interface HOCOpts<S> {
    // Wraps the page without any CSRF meta tag to context. This allows such pages to be cached,
    // such as publicly visible landings pages
    withoutAnyCSRF?: boolean;

    // Wraps the page with a CSRF meta tag and AntiCSRF context, but doesn't attempt to verify that
    // the URL contains a `_csrfToken` query paramter. You will generally want this option enabled,
    // but be careful: if your page is server-side rendered you may be susceptible to timing and DoS
    // attacks. However, disabling this option (the default) requires navigating to the affected
    // page from somewhere that has added a `_csrfToken` query paramter to the URL (see the
    // `useAntiCSRF` hook for generating these links)
    withoutQueryCSRF?: boolean;

    // On authentication failure render a fallback UI
    fallback?: React.ReactNode;

    // When the `getInitialProps` for the wrapped page runs it will call the provided `redirect`
    // callback. If the callback returns a string, then its used as a redirect URL, otherwise the
    // page renders normally. Useful for redirecting when authentication fails. Example:
    //
    //  ```ts
    //  {
    //      redirect: ({ isloggedin }) => !isloggedin ? '/login' : null
    //  }
    //  ```
    redirect?: (auth: AuthClient<S>, context: NextPageContext) => string | null;
}

export type InitialProps<P, S> = P & { auth: AuthClient<S> };

interface AntiCSRF {
    verify(token: string): boolean;
    hoc<P>(Component: NextPage<P>): NextPage<P & { csrfToken: string }>;
}

const AuthSessionContext = createContext<AuthClient<any>>({
    loggedin: false,
});

export class Authenticator<P, S> {
    constructor(
        public decode: (token: string) => P | undefined,
        public extract: (payload: P) => S,
        public csrf?: AntiCSRF,
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

    // React hook for reading the auth session
    useAuthSession(): AuthClient<S> {
        // eslint-disable-next-line react-hooks/rules-of-hooks
        return useContext(AuthSessionContext);
    }

    // HOC that wraps a nextjs page component with a AuthSessionContext. We attempt to get the auth
    // session and pass it to the context provider
    hoc<Props>(Component: NextPage<Props>, opts?: HOCOpts<S>): NextPage<InitialProps<Props, S>> {
        let getAuthServer: (req: IncomingMessage, res: ServerResponse) => Promise<AuthServer<P, S>>;

        if (opts?.withoutAnyCSRF || opts?.withoutQueryCSRF) {
            getAuthServer = (req, res) => this.fromCookieWithoutCSRF(req, res);
        } else {
            getAuthServer = (req, res) => this.fromCookie(req, res);
        }

        class WithAuthSession extends React.Component<InitialProps<Props, S>> {
            static async getInitialProps(nextContext: NextPageContext) {
                const { req, res } = nextContext;
                if (req !== undefined && res !== undefined) {
                    const authServer = await getAuthServer(req, res);
                    const authClient = authServerToClient(authServer);

                    if (opts?.redirect) {
                        const Location = opts.redirect(authClient, nextContext);
                        if (Location !== null) {
                            res.writeHead(302, { Location });
                            res.end();
                        }
                    }

                    if (Component.getInitialProps) {
                        return {
                            auth: authClient,
                            ...(await Component.getInitialProps(nextContext)),
                        };
                    } else {
                        return { auth: authClient };
                    }
                }

                return { auth: { loggedin: false } };
            }

            render() {
                const { auth, ...props } = this.props;
                if (opts?.fallback && !auth.loggedin) {
                    return opts.fallback;
                }
                return (
                    <AuthSessionContext.Provider value={auth}>
                        <Component {...(props as Props)} />
                    </AuthSessionContext.Provider>
                );
            }
        }

        if (opts?.withoutAnyCSRF) {
            return WithAuthSession as any;
        } else {
            if (this.csrf === undefined) {
                throw Error('AntiCSRF instance not provided');
            }
            return this.csrf.hoc(WithAuthSession as any) as any;
        }
    }
}

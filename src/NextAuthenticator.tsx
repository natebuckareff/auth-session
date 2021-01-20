import { IncomingMessage, ServerResponse } from 'http';
import { NextPage, NextPageContext } from 'next';
import React, { createContext, useContext } from 'react';
import { AuthClient, Authenticator, AuthServer } from './Authenticator';
import { NextAntiCSRF } from './NextAntiCSRF';

export const AuthSessionContext = createContext<AuthClient<any>>({
    loggedin: false,
});

export interface Options<S> {
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
    // page renders normally. Useful for redirecting when authentication fails
    redirect?: (auth: AuthClient<S>, context: NextPageContext) => string | null;
}

export type InitialProps<P, S> = P & { auth: AuthClient<S> };

export class NextAuthenticator<P, S = P> extends Authenticator<P, S, NextAntiCSRF> {
    // HOC that wraps a nextjs page component with a AuthSessionContext. We attempt to get the auth
    // session and pass it to the context provider
    hoc<Props>(Component: NextPage<Props>, opts?: Options<S>): NextPage<InitialProps<Props, S>> {
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

    // React hook for reading the auth session
    useAuthSession(): AuthClient<S> {
        // eslint-disable-next-line react-hooks/rules-of-hooks
        return useContext(AuthSessionContext);
    }
}

function authServerToClient<T, S>(authServer: AuthServer<T, S>): AuthClient<S> {
    if (authServer.loggedin) {
        return { loggedin: true, state: authServer.state };
    } else {
        return authServer;
    }
}

import CSRFTokens from 'csrf';
import { NextPage, NextPageContext } from 'next';
import Head from 'next/head';
import React, { FC, useCallback, useContext } from 'react';

const AntiCSRFContext = React.createContext<string | null>(null);

// Create and verify anti-CSRF tokens and wrap nextjs page components in a HOC that adds anti-CSRF
// tokens as a meta tag and provides it to react elements through a context

export class AntiCSRF {
    private csrfTokens: CSRFTokens = new CSRFTokens();

    constructor(private secretKey: string) {}

    create(): string {
        return this.csrfTokens.create(this.secretKey);
    }

    verify(token: string): boolean {
        return this.csrfTokens.verify(this.secretKey, token);
    }

    hoc<P>(Component: NextPage<P>): NextPage<P & { csrfToken: string }> {
        type Props = P & { csrfToken: string };

        const csrfToken = this.create();

        return class WithAntiCSRF extends React.Component<Props> {
            static async getInitialProps(context: NextPageContext) {
                if (Component.getInitialProps) {
                    return {
                        csrfToken,
                        ...(await Component.getInitialProps(context)),
                    };
                } else {
                    return { csrfToken };
                }
            }

            render() {
                const { csrfToken, ...props } = this.props;
                return (
                    <AntiCSRFContext.Provider value={csrfToken}>
                        <Head>
                            <meta
                                key={`csrf-token-${csrfToken}`}
                                name="csrf-token"
                                content={csrfToken}
                            />
                        </Head>
                        <Component {...(props as P)} />
                    </AntiCSRFContext.Provider>
                );
            }
        } as NextPage<Props>;
    }
}

export interface UseAntiCSRF {
    token: string | null;
    url(path: string, params?: Record<string, string>): string;
}

// Attempts to read the page's anti-CSRF token. Also provides a utility function that appends the
// token to URLS (for protecting page loads from timing attacks)
export function useAntiCSRF(): UseAntiCSRF {
    const token = useContext(AntiCSRFContext);
    const url = useCallback(
        (path: string, params?: Record<string, string>) => {
            if (path.includes('?')) {
                throw Error('invalid URL path');
            }
            params = params ?? {};
            params['_csrfToken'] = token ?? '';
            const pairs: string[] = [];
            for (const k in params) {
                pairs.push(`${k}=${params[k]}`);
            }
            return `${path}?${pairs.join('&')}`;
        },
        [token],
    );
    return { token, url };
}

// Helper for adding anti-CSRF tokens to forms. Useful for simple sites and/or nojs
export const AntiCSRFInput: FC<React.HTMLProps<HTMLInputElement>> = props => {
    const { token } = useAntiCSRF();
    if (token) {
        return <input type="hidden" name="_csrfToken" value={token} {...props} />;
    }
    return null;
};

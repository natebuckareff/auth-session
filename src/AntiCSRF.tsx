import CSRFTokens from 'csrf';
import React, { FC, useCallback, useContext } from 'react';

export const AntiCSRFContext = React.createContext<string | null>(null);

// Create and verify anti-CSRF tokens and wrap nextjs page components in a HOC that adds anti-CSRF
// tokens as a meta tag and provides it to react elements through a context

export class AntiCSRF {
    private csrfTokens?: CSRFTokens;

    constructor(private secretKey: string) {}

    private getTokens() {
        // Create CSRFTokens lazily
        if (this.csrfTokens === undefined) {
            this.csrfTokens = new CSRFTokens();
        }
        return this.csrfTokens;
    }

    create(): string {
        return this.getTokens().create(this.secretKey);
    }

    verify(token: string): boolean {
        return this.getTokens().verify(this.secretKey, token);
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

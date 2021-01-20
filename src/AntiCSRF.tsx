import CSRFTokens from 'csrf';

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

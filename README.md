# Overview

Simple cookie session management for [Next.js][1] applications.

[1]: https://github.com/vercel/next.js

## Usage

### new Authenticator<P, S = P>(decode, extract, csrf)

`decode` is a callback that parses the stringified cookie value.

`extract` is a callback that pulls out values from the decoded cookie value that are passed to
the client.

`csrf` is an `AntiCSRF` instance for creating and verifying anti-CSRF tokens.

Example:

```ts
export const authenticator = new Authenticator<{ userId: string }>(
    token => AuthToken.verify(token),
    payload => ({ userId: payload.access.userId }),
    new AntiCSRF(SECRET_KEY)
);
```

### Authenticator.setCooke(req, res, payload, token)

`req` is a node request object.

`res` is a node response object.

`payload` is the parsed version of `token`.

`token` is the stringified data stored in the cookie.

Example:

```ts
export async function login(req, res) {
    const { username, password } = parseLoginRequest(req);
    const user = await db.user.getOne({ username });
    const payload = { userId: user.id }
    const jwt.sign(payload, SECRET_KEY, {
        expiresIn: '24h',
        mutatePayload: true
    });

    authenticator.setCookie(req, res, payload, token);

    res.statusCode = 200;
    res.redirect(`/loggedin`);
    res.end();
}
```

### Authenticator.removeCookie(req, res)

`req` is a node request object.

`res` is a node response object.

Example:

```ts
export function logout(req, res) {
    authenticator.removeCookie(req, res);

    res.statusCode = 200;
    res.redirect(`/`);
    res.end();
}
```

### Authenticator.fromCookie(req, res, [body])

`req` is a node request object.

`res` is a node response object.

`body` is the preparsed request body as an object.

Example:

```ts
export async function getBillingData(req, res) {
    const auth = await authenticator.fromCookie(req, res);

    if (!auth.loggedin) {
        res.status(401).json({ error: auth.error ?? 'authorization failed' });
        return;
    }

    const report = await db.report.getOneMaybe({
        userId: auth.state.userId,
        type: 'billing'
    });

    res.status(200).json({ data: report });
}
```

### Authenticator.fromCookieWithoutCSRF(req, res)

This is the same as `fromCookie`, but without anti-CSRF token verification. Useful for just
reading the cookie data.

Example:

```ts
export async function isLoggedIn(req, res) {
    const auth = await authenticator.fromCookieWithoutCSRF(req, res);
    res.status(200).json({ data: auth.loggedin });
}
```

### Authenticator.useAuthSession()

React hook for reading the `AuthSession` context

Example:

```ts
// in auth.ts
export const { useAuthSession } = authenticator;

// in page.tsx
import { useAuthSession } from './auth'

const MyComponent: FC = () => {
    const auth = useAuthSession()
    ...
}
```

### Authenticator.hoc<Props>(Component, [opts])

Higher-order component that wraps a `NextPage` component with cookie authentication. Uses
`getInitialProps`.

`opts`:

- `withoutAnyCSRF` wraps the page without any CSRF meta tag to context. This allows such pages to
be cached,such as publicly visible landings pages

- `withoutQueryCSRF` wraps the page with a CSRF meta tag and AntiCSRF context, but doesn't
attempt to verify that the URL contains a `_csrfToken` query paramter. You will generally want
this option enabled, but be careful: if your page is server-side rendered you may be susceptible
to timing and DoS attacks. However, disabling this option (the default) requires navigating to
the affected page from somewhere that has added a `_csrfToken` query paramter to the URL (see the
`useAntiCSRF` hook for generating these links) withoutQueryCSRF?: boolean;

- `fallback` on authentication failure render a fallback UI

- `redirect` when the `getInitialProps` for the wrapped page runs it will call the provided
callback. If the callback returns a string, then its used as a redirect URL, otherwise the page
renders normally. Useful for redirecting when authentication fails

```ts
const HomePage: NextPage = () => {
    ...
}

export default authenticator.hoc(HomePage, {
    withoutAnyCSRF: true,
    redirect: ({ loggedin }) => (loggedin ? '/secret-stuff' : null),
});
```
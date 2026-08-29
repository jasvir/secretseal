<p align="center">
  <img src="assets/secretseal-logo.png" alt="A cartoon seal protectively holding a sealed envelope" width="240">
</p>

# Secret Seal: How can I prevent secrets from leaking from an HTTP request?

## Leak-resistant browser requests

Browser applications routinely send authentication tokens, personally identifiable information (PII), and other sensitive values through infrastructure that was built for observability and performance rather than secrecy. A request may pass through browser history, an HTTP cache, a service worker, a browser extension, a CDN, a load balancer, a reverse proxy, an application framework, tracing instrumentation, exception reporting, and several log stores before it reaches its final handler.

TLS protects a request while it is travelling between TLS endpoints. It does not stop those endpoints—or software running behind them—from storing, copying, indexing, or logging the request. In practice, no part of an HTTP request can be completely relied upon to prevent a leak. URLs are copied into histories and access logs; recognized credential headers can still appear in request dumps; unfamiliar headers may escape redaction; cookies are deliberately persisted; fragments are exposed to page code and occasionally reach servers; and request bodies are frequently captured by error and diagnostic tooling.

The useful question is therefore not *where can a secret be made impossible to leak?* but *which carrier minimizes the likely exposure for a particular threat model, and what additional controls reduce the remaining risk?*

For the short version, go directly to the [list of request carriers and their leakage pitfalls](#summary-table).

This document compares the accidental-disclosure properties of common places in which browser applications put sensitive values. It concentrates on accidental persistence and disclosure, not on an attacker who has fully compromised the origin or browser. If malicious JavaScript can act with the same authority as the application, it can usually read data available to the application or cause the application to use credentials on its behalf.

The central rule is simple:

> No part of an HTTP request should be considered intrinsically safe for raw PII, long-lived credentials, or private cryptographic keys.

Nevertheless, some carriers are considerably less accident-prone than others.

## Relationship to the OWASP Top 10

The [OWASP Top 10:2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/) recognizes sensitive-data and credential exposure across several root-cause categories rather than as a single vulnerability:

- [A02: Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/) includes insecure cookie configuration and excessive error detail.
- [A04: Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/) covers missing or inadequate encryption, leaking cryptographic keys, and determining when sensitive data requires application-layer protection in addition to TLS.
- [A06: Insecure Design](https://owasp.org/Top10/2025/A06_2025-Insecure_Design/) maps weaknesses involving sensitive browser caches, persistent cookies containing sensitive information, and sensitive values in GET query strings.
- [A07: Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/) warns against exposing session identifiers in URLs or other insecure client-visible locations and recommends secure, server-managed sessions.
- [A09: Security Logging and Alerting Failures](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/) explicitly includes placing sensitive information such as PII or protected health information in logs.
- [A10: Mishandling of Exceptional Conditions](https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/) includes sensitive information in error messages and debugging output.

Earlier editions described the outcome more directly as [A3:2017 Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure). The newer organization favors underlying causes. That is useful for classifying vulnerabilities, but it makes the complete request-leakage problem less visible in any one entry.

The Top 10 is an awareness and risk-classification document, not a detailed comparison of HTTP request carriers. Supporting OWASP guidance correctly advises that [credentials should not appear in URLs](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html#sensitive-information-in-http-requests), that [sensitive values should usually be excluded from logs](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html#data-to-exclude), and that [session identifiers should be opaque](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-content-or-value). It does not provide a consolidated comparison of how URLs, standard and custom headers, cookies, fragments, bodies, tracing context, errors, caches, and observability systems create and retain copies of the same value.

This document is intended to fill that narrower implementation gap. It does not replace the OWASP guidance: it applies that guidance to the concrete question of where browser-request data accumulates, why some carriers are less accident-prone than others, and which additional controls are needed when sensitive transmission cannot be avoided.

## Summary table

The ratings below describe common browser and infrastructure behaviour, not a protocol guarantee. A deployment can make any row worse through configuration. A linked seal, [🦭](#authorization), leads to further discussion.

| Carrier | Browser persistence or history | Browser Performance Timeline | Ordinary access logs | Error, debug, and trace capture | Same-origin JavaScript | Potential Exposure | Appropriate use |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `Authorization: Bearer …` [🦭](#authorization) | Low for application-supplied bearer tokens; browser-managed HTTP authentication may be retained separately | Low: the API exposes URLs, not header values | Usually low because many systems recognize it as sensitive | Medium: redaction is common but not universal | High when the application owns the token | First Party Scripts<br>Third Party Scripts<br>Browser Cache/Storage/History<br>CDN/Proxy/TLS termination<br>Tracing/Debugging/Extensions<br>Logging at Origin<br>Downstream Services | Short-lived, scoped API credentials |
| `Cookie` with `Secure; HttpOnly; SameSite` [🦭](#cookies) | High by design: the browser stores it | Low: the API does not expose cookie values | Usually low, but highly configuration-dependent | Medium: full request dumps may include it | Low for directly reading an `HttpOnly` value; high for causing authenticated requests | Browser Cache/Storage/History<br>CDN/Proxy/TLS termination<br>Tracing/Debugging/Extensions<br>Logging at Origin<br>Downstream Services | Opaque browser session identifiers |
| `Proxy-Authorization` | Low | Low: the API does not expose the header value | Usually low at the origin; visible to the authenticating proxy | Medium | Usually low | CDN/Proxy/TLS termination<br>Tracing/Debugging/Extensions | Proxy authentication only; never repurpose it |
| Custom secret header such as `X-API-Key` [🦭](#custom-secret-headers) | Low unless application code persists the value | Low: the API exposes URLs, not header values | Usually low in traditional access-log formats | Medium–high because generic redactors may not recognize it | High | First Party Scripts<br>Third Party Scripts<br>Browser Cache/Storage/History<br>CDN/Proxy/TLS termination<br>Tracing/Debugging/Extensions<br>Logging at Origin<br>Downstream Services | Machine or API credentials when `Authorization` cannot be used |
| Request body [🦭](#request-bodies) | Usually low in browser history and HTTP caches | Low: the API does not expose the body | Usually low in traditional access logs | High in practice, especially on errors | High | First Party Scripts<br>Third Party Scripts<br>CDN/Proxy/TLS termination<br>Tracing/Debugging/Extensions<br>Logging at Origin<br>Downstream Services | Necessary PII or structured sensitive input, with minimization and redaction |
| URL fragment [🦭](#url-fragments) | High until removed; may enter history and history sync | High when retained in a navigation or resource entry; browser-dependent | Low, but not zero in operational reality | Medium in browser telemetry and page-level error reports | Very high | First Party Scripts<br>Third Party Scripts<br>Browser Cache/Storage/History<br>Tracing/Debugging/Extensions<br>Downstream Services | Narrow, isolated bootstrap and split-knowledge designs only |
| URL path or query string [🦭](#url-paths-and-query-strings) | Very high | Very high: navigation and resource entries expose request URLs | Very high | Very high | Very high | First Party Scripts<br>Third Party Scripts<br>Browser Cache/Storage/History<br>CDN/Proxy/TLS termination<br>Tracing/Debugging/Extensions<br>Logging at Origin<br>Downstream Services | Non-sensitive routing and filtering values only |
| `Referer`, `User-Agent`, `Forwarded`, or `X-Forwarded-For` | Medium | Low: these request headers are not exposed | Very high | High | Varies | First Party Scripts<br>Third Party Scripts<br>Browser Cache/Storage/History<br>CDN/Proxy/TLS termination<br>Tracing/Debugging/Extensions<br>Logging at Origin<br>Downstream Services | Protocol metadata only; never repurpose for secrets |
| Tracing `baggage` or similar context [🦭](#tracing-and-baggage) | Usually low | Low unless copied into a URL | High across downstream telemetry | Very high by design | High when created in the browser | First Party Scripts<br>Third Party Scripts<br>CDN/Proxy/TLS termination<br>Tracing/Debugging/Extensions<br>Logging at Origin<br>Downstream Services | Non-sensitive correlation metadata only |

“Low” does not mean “safe.” It means that the value is less likely to appear in that particular sink under conventional defaults.

## Why HTTP caching is only part of the problem

[RFC 9111](https://www.rfc-editor.org/rfc/rfc9111.html) defines an HTTP cache key as, at minimum, the request method and target URI. Many caches only cache `GET` responses and primarily use the URI as the key. Request header fields can become part of cache matching when a response names them in `Vary`.

Sensitive headers should therefore never be named in `Vary`:

```http
Vary: X-API-Key  # unsafe design
```

A cache processing that response must retain enough information to distinguish the original header values. `Authorization` does not need to appear in `Vary`; authenticated requests have special shared-cache rules.

For a sensitive exchange, both requests and responses can use:

```http
Cache-Control: no-store
```

For Fetch, the corresponding client instruction is:

```js
await fetch(url, {
  cache: "no-store",
  headers: { Authorization: `Bearer ${token}` },
});
```

`no-store` instructs compliant private and shared caches not to store the immediate request or response. RFC 9111 explicitly warns that it is not a sufficient privacy mechanism. It does not govern application logs, access logs, exception reports, traces, packet capture, browser extensions, or a compromised intermediary. `private` is weaker: it permits storage in a private browser cache while prohibiting shared-cache storage.

HTTP/2 HPACK and HTTP/3 QPACK header-compression tables are also distinct from HTTP response caches. HPACK provides a “never indexed” representation for sensitive fields and names `Cookie` and `Authorization` as examples, but use of that representation remains an implementation concern. It is useful defence in depth, not an application security boundary.

## The logging reality

Traditional access-log formats commonly record the request line—which contains the URL—along with the referrer and user agent. For example, the predefined [nginx combined log format](https://nginx.org/en/docs/http/ngx_http_log_module.html) does not include arbitrary request headers or the request body. This gives `Authorization`, cookies, custom headers, and bodies a lower *default access-log* exposure than URLs.

That advantage frequently disappears elsewhere in the stack. In real systems, exception middleware, debug logging, API gateways, request inspectors, and error-reporting tools often serialize a complete request when an operation fails. Some deployments do the same for ordinary structured logs. A particularly common partial safeguard is to redact `Authorization` while retaining cookies, unfamiliar custom headers, parsed form fields, and the complete request body.

This practice conflicts with the [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), which recommends removing, masking, hashing, sanitizing, or encrypting access tokens, session identifiers, encryption keys, and sensitive personal data rather than recording them directly. The gap between recommended practice and operational practice means that request bodies and unrecognized headers should be assumed loggable.

Observability instrumentation creates a similar risk. The [OpenTelemetry HTTP semantic conventions](https://opentelemetry.io/docs/specs/semconv/registry/attributes/http/) recommend explicit configuration of which request headers may be captured because capturing all headers can disclose sensitive information.

Logs remain security-sensitive assets even when raw secrets have been excluded. Access to them should be restricted and audited, their integrity should be protected, and retention and deletion periods should be explicit. Collection must also have an appropriate legal and organizational basis: operational usefulness is not by itself sufficient reason to retain personal data. These controls limit the harm caused by safe derived identifiers and contextual data being combined, queried, or disclosed.

## Authorization

`Authorization` is generally the least accident-prone HTTP header for a bearer credential because the ecosystem knows what it means:

- HTTP caching gives authenticated requests special shared-cache treatment.
- HTTP header-compression implementations can treat it as never-indexed.
- proxies, frameworks, and observability products frequently include it in default redaction lists.
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) recommends the `Authorization` header for OAuth bearer tokens and warns against putting bearer tokens in page URLs.

These are conventions, not confidentiality guarantees. The header is visible at every TLS endpoint and every application layer through which the decoded request passes. A full request dump, incorrectly configured trace exporter, or custom proxy can still record it.

Bearer credentials should be short-lived, audience-restricted, narrowly scoped, and replaceable. A cryptographic private key should not be transmitted in `Authorization` or anywhere else in an HTTP request.

## Cookies

An opaque session identifier in a cookie with `Secure`, `HttpOnly`, and an appropriate `SameSite` setting is usually preferable to exposing an API token to application JavaScript. `HttpOnly` prevents ordinary page scripts from directly reading the cookie; it does not prevent those scripts from causing the browser to make authenticated requests.

Cookies are deliberately stored by browsers and sent automatically to matching destinations. They may therefore be present in browser profiles, backups, developer tools, endpoint inspection products, sufficiently privileged extensions, proxies, and server-side request dumps. Cookie values should be opaque references to server-side state rather than containers for raw PII. The `__Host-` prefix can further constrain a session cookie's scope.

For browser OAuth clients, [RFC 10017](https://www.rfc-editor.org/rfc/rfc10017.html) presents a backend-for-frontend (BFF) as the strongest of its principal architecture patterns: OAuth tokens remain at the backend and the browser holds only a cookie-backed session. Malicious page code can still act through the user's browser, but it cannot directly extract the backend tokens.

## Custom secret headers

A custom header such as `X-API-Key` avoids browser history, referrer propagation, and conventional request-line logging. It is not necessarily safer than `Authorization`, because generic infrastructure may not recognize the header as sensitive.

Every custom credential header should be registered with redaction policy at all of the following layers:

- browser or frontend telemetry;
- CDN and edge request logging;
- load balancers and reverse proxies;
- application request and error serializers;
- distributed tracing and APM;
- support tooling and request replay systems.

A custom secret header must not be included in `Vary`. Cross-origin use also causes a CORS preflight in ordinary Fetch configurations; the preflight exposes the header name, not its value.

## Request bodies

Request bodies avoid the browser-history, referrer, and conventional access-log problems of URLs. HTTP caches also primarily store responses, and `POST` responses are not ordinarily keyed by request body content.

Bodies nevertheless have high practical logging exposure. Frameworks commonly parse them into convenient objects, after which exception handlers and structured loggers can serialize them. Validation failures are especially dangerous: the invalid input is often attached to the error precisely to make debugging easier. Proxies and APM agents may capture the raw body before application-level redaction runs.

Necessary PII belongs in a body rather than in a URL or arbitrary header, but it should still be minimized. Schemas should classify sensitive fields, and log serializers should operate on an allowlisted safe view rather than serializing the parsed request and deleting a few known keys afterward.

Application-layer encryption can keep selected body fields opaque to CDNs, TLS-terminating gateways, and early request logging. It does not help after decryption unless the resulting value retains its sensitive classification throughout the application.

## URL fragments

Under the URI, HTTP, and Referrer Policy specifications, the fragment is interpreted by the client. A conforming browser does not include it in the HTTP request target or in the `Referer` header.

Operationally, fragment values do sometimes appear at servers. The cause is not always known. Plausible sources include nonconforming or embedded user agents, extensions, client-side code that copies `location.href` or `location.hash` into another request, analytics and error telemetry, native wrappers, and other intermediating software. A fragment should therefore be treated as *unlikely* to reach ordinary server infrastructure, not as cryptographically prevented from doing so.

The fragment is directly visible to every same-page script through `window.location`. It can also appear in browser history, synced history, copied URLs, screenshots, crash reports, session-replay tools, and extension APIs. OAuth's former Implicit flow returned access tokens in fragments; [RFC 10017 now prohibits that flow](https://www.rfc-editor.org/rfc/rfc10017.html#section-7.2), in part because any third-party or malicious script on the page can read the token.

When a fragment is used for a narrowly scoped bootstrap value, it should be removed before third-party code loads:

```html
<script>
  const bootstrapValue = location.hash.slice(1);
  history.replaceState(null, "", location.pathname + location.search);
</script>
```

This script should be the first executable content on an isolated landing page. The page should avoid third-party scripts, use a strict Content Security Policy, avoid redirects before cleanup, and keep the value only as long as needed. Cleanup reduces exposure but cannot undo capture that occurred before `replaceState` executed.

### Performance Timeline retains request URLs

Removing a fragment from `window.location` and browser history does not necessarily remove it from the browser's Performance Timeline. [Navigation Timing](https://w3c.github.io/navigation-timing/#marking-navigation-timing) initializes the navigation entry from the document's URL, and [Resource Timing](https://w3c.github.io/resource-timing/#sec-performanceresourcetiming) stores requested resource URLs in performance entries. The [HTML history update steps](https://html.spec.whatwg.org/dev/browsing-the-web.html#url-and-history-update-steps) used by `history.replaceState` change the document and session-history URL but do not rewrite an already-created performance entry.

Same-origin code that runs later may therefore be able to recover an initial navigation URL or the URLs of earlier Fetch, XHR, image, script, and other resource requests:

```js
const initialURL = performance.getEntriesByType("navigation")[0]?.name;
const resourceURLs = performance
  .getEntriesByType("resource")
  .map(entry => entry.name);
```

The Performance APIs expose URLs and timing metadata rather than request headers or bodies. They do not directly reveal an `Authorization` value, cookie, or body field unless application code also placed that value in a URL. Browser handling of fragments varies, particularly for special fragment directives, so an application should conservatively assume that an ordinary fragment can remain available through a navigation or resource entry after visible cleanup.

`performance.clearResourceTimings()` can remove buffered resource entries, but there is no corresponding standard operation for clearing the current navigation entry. Clearing also cannot retract a value already copied by a `PerformanceObserver`, analytics library, logging or tracing client, browser extension, or earlier script.

If later page code must not be able to recover the bootstrap URL, the bootstrap should run in a minimal isolated document and then transition to a genuinely new document whose initial URL never contained the fragment. Merely removing or replacing the fragment in the same document is not sufficient. The new document should be loaded before third-party, analytics, logging, tracing, or other nonessential code is introduced.

Given these complications, a fragment is not a leak-proof place to store raw PII, reusable credentials, or secret tokens when logging, tracing, analytics, or malicious code can run with first-party authority. At most, it should carry a narrowly scoped, short-lived, single-use bootstrap value or decryption key whose disclosure has been explicitly considered in the threat model.

### Fragment-held decryption keys

A specialised split-knowledge design can place ciphertext in a server-visible location and its decryption key in the fragment. The server, CDN, and conventional request logs then see ciphertext while the page can decrypt it locally.

A framework implementing this pattern should provide:

- authenticated encryption rather than unauthenticated encryption;
- a fresh high-entropy key for each payload;
- expiry and replay protection;
- immediate fragment removal;
- an isolated bootstrap document with no third-party code;
- a transition to a new clean document before loading less-trusted application or telemetry code, when the original navigation URL must no longer be observable;
- explicit binding of the ciphertext to its intended origin and purpose;
- zero plaintext logging after decryption.

This design protects plaintext from server-side caches and early logging. It does not protect against browser-history capture before cleanup, malicious same-origin JavaScript, extensions, compromised browser profiles, or code that can observe the decrypted value. If the ciphertext and key are both recoverable from the original full URL, anyone possessing that URL can decrypt the PII.

## URL paths and query strings

Paths and query strings have the broadest accidental-disclosure surface. They commonly appear in:

- browser history and history synchronization;
- bookmarks, copied links, screenshots, and support tickets;
- CDN, load-balancer, proxy, and web-server access logs;
- cache keys;
- analytics and session-replay products;
- same-origin `Referer` headers and, under weaker policies, cross-origin referrers;
- metrics labels and error messages;
- allowlists, blocklists, and security-product event stores.

The current default referrer policy, `strict-origin-when-cross-origin`, still sends the full path and query on same-origin requests. `Referrer-Policy: no-referrer` reduces propagation but does not remove any of the other sinks.

URLs should contain opaque, short-lived, single-use handles rather than PII or bearer credentials. [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.3) discusses even short-lived OAuth authorization codes as a browser-history exposure and relies on replay prevention and prompt cleanup.

## Tracing and baggage

Distributed tracing is designed to propagate context across process boundaries. That makes tracing metadata one of the worst places for sensitive data.

OpenTelemetry baggage may be forwarded automatically to downstream services and then copied into spans, metrics, and logs. Its own [security guidance](https://opentelemetry.io/docs/concepts/signals/baggage/#baggage-security-considerations) warns that sensitive baggage can reach unintended resources, including third-party APIs. Credentials, raw user identifiers, email addresses, health information, and other PII should not be placed in `baggage`, `tracestate`, correlation headers, or metric labels.

## Framework facilities that can provide stronger protection

Choosing a carrier is a local decision. Preventing leaks is an end-to-end property. A framework can provide protections that are difficult for each application team to implement consistently.

### 1. Sensitivity-aware values and taint propagation

The framework can represent sensitive data as a distinct runtime and type-system value rather than as an ordinary string:

```ts
const email = Sensitive.pii(input.email);
const token = Sensitive.credential(accessToken);

logger.info({ email });                    // emits "[REDACTED]"
url.searchParams.set("email", email);      // compile-time or runtime error
request.setBaggage("token", token);        // error
request.json({ email });                   // allowed by an explicit route policy
```

The difficult part is preserving the label through parsing, validation, string interpolation, exceptions, queues, database objects, RPC boundaries, and asynchronous callbacks. A framework can own those transitions and require explicit declassification before a value enters an unsafe sink.

Sensitivity metadata should distinguish at least:

- credentials and session identifiers;
- cryptographic key material;
- direct PII;
- linkable pseudonymous identifiers;
- financial or health data;
- values safe for public logging.

### 2. Schema-derived redaction

Request and response schemas can classify fields once and generate:

- parser and validator behaviour;
- safe structured-log views;
- trace-attribute allowlists;
- support-tool displays;
- data-retention rules;
- application-layer encryption policies.

This is safer than maintaining separate, name-based redaction lists in every logger. Name-based lists routinely miss aliases such as `secret`, `apiKey`, `credential`, `assertion`, nested values, arrays, or values embedded in free-form strings.

### 3. A safe request representation for logs and errors

Instead of giving loggers access to the raw request object, a framework can expose only a deliberately lossy representation:

```json
{
  "method": "POST",
  "route": "/users/:id",
  "status": 400,
  "request_bytes": 842,
  "content_type": "application/json",
  "request_id": "…"
}
```

Raw headers and bodies can be unavailable by default, including in exception objects. Where correlation is necessary, the framework can log a keyed HMAC fingerprint rather than the original credential or identifier. Temporary raw capture should require a narrowly scoped break-glass policy, short retention, access auditing, and automatic deletion.

Any user-controlled value that is retained must also be structurally encoded before it enters a log. Redaction protects confidentiality; encoding separately prevents line breaks, delimiters, or other crafted input from forging log entries or attacking downstream log processors.

### 4. Automatic cache and referrer policy

Routes classified as sensitive can automatically receive:

```http
Cache-Control: no-store
Referrer-Policy: no-referrer
```

The framework can reject contradictory `public` or `s-maxage` directives, reject sensitive headers named in `Vary`, disable body capture, and prevent sensitive values from becoming cache tags or surrogate keys. It can also redirect a completed one-time exchange to a clean URL so that the working page never retains the bootstrap URL.

### 5. One-time opaque handles

The safest URL value is often a random handle with no meaning outside a short redemption window. A framework can make handle exchange a primitive:

1. Generate a high-entropy, purpose-bound, expiring handle.
2. Bind it to the expected origin, client, and action.
3. Permit exactly one successful redemption.
4. Exchange it for server-side state or an `HttpOnly` session cookie.
5. Redirect to a clean URL.
6. Retain only a non-reversible audit fingerprint.

This pattern is easy to describe but difficult to implement correctly under retries, concurrent tabs, back-button navigation, clock skew, partial failure, and replay. Those are good reasons to centralize it.

### 6. Application-layer encrypted fields

For particularly sensitive bodies, a framework can encrypt selected fields before the request reaches a CDN or TLS-terminating gateway. A standard construction such as [HPKE](https://www.rfc-editor.org/rfc/rfc9180.html), embedded in an application protocol with replay protection and authenticated context, can ensure that early infrastructure sees only ciphertext.

The decrypting service must recreate sensitivity-aware values rather than ordinary strings; otherwise the first post-decryption exception can put the plaintext back into logs. Key rotation, algorithm negotiation, payload binding, replay detection, and failure handling should be framework responsibilities rather than application code.

### 7. Credential brokers

A server-side BFF can hold API credentials and expose only an opaque browser session. It can add `Authorization` only on outbound requests to allowlisted resource origins, enforce method and path restrictions, rate-limit operations, and remove credentials before redirects or error serialization.

A worker-based broker can keep a token outside the main page's JavaScript heap and attach it to outbound requests. This reduces direct token extraction, but it is not equivalent to a BFF. RFC 10017 explains that service-worker OAuth patterns remain vulnerable to new token acquisition and browser-mediated request proxying, and therefore does not recommend the service-worker pattern as a general solution.

### 8. Sender-constrained and per-request credentials

Frameworks can reduce the value of a copied bearer token by using sender-constrained tokens such as [DPoP](https://www.rfc-editor.org/rfc/rfc9449.html), non-exportable WebCrypto keys, short lifetimes, narrow audiences, and per-request proofs bound to a method and URL.

These mechanisms reduce off-device replay. They do not defeat malicious same-origin JavaScript that can ask the legitimate browser to make requests or obtain new credentials. A non-exportable key prevents extraction of key bytes; it does not prevent authorized code—or malicious code with the same privileges—from invoking the key.

### 9. Egress and redirect controls

A framework can maintain an origin-level egress policy and automatically:

- strip credentials and sensitive context on cross-origin redirects;
- prevent forwarding `Cookie`, `Authorization`, and custom credentials to unapproved origins;
- remove tracing baggage at trust boundaries;
- require explicit opt-in for credentialed CORS;
- distinguish public telemetry endpoints from trusted application APIs;
- reject attempts to copy a complete current URL into a header, body, or telemetry event.

These controls are most effective below application code, where a forgotten Fetch wrapper or new HTTP client cannot bypass them accidentally.

### 10. Leak-canary testing

A testing framework can inject unique, non-functional canary values into every sensitive carrier, then exercise:

- successful and failing requests;
- validation and parsing errors;
- redirects and authentication challenges;
- retry and timeout paths;
- browser history and storage;
- service workers and offline caches;
- CDN, proxy, application, trace, metric, and error-reporting stores.

The test fails if a canary appears outside its declared destinations. Because each carrier receives a different canary, the result identifies the leaking path. This turns redaction from a configuration claim into an observable security property.

These leak canaries serve a different purpose from the [honeytokens recommended by OWASP A09](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/#how-to-prevent). A honeytoken is a trap whose unexpected use or access signals possible attacker activity. A leak canary is test data whose appearance in an undeclared cache, log, trace, error report, or other sink demonstrates accidental propagation. A system may use both, but their alert conditions and handling should remain distinct.

### 11. Retention and deletion orchestration

Once sensitive data reaches logs or telemetry, removing it is often harder than preventing collection. A framework can attach retention classes to safe derived events, prevent high-sensitivity data from entering long-retention stores, track which processors received a value, and automate cache and telemetry deletion after an incident.

This cannot guarantee deletion from unknown intermediaries, immutable backups, or a recipient outside the framework. It can substantially reduce the number of systems that must be trusted.

## Preferred hierarchy

For a new browser application, the general order of preference is:

1. Do not transmit the sensitive value at all.
2. Replace it with an opaque, short-lived, single-use server-side handle.
3. Keep API tokens in a BFF and give the browser an opaque `Secure; HttpOnly; SameSite` session cookie.
4. When the browser must call an API directly, use a short-lived, scoped `Authorization` credential held in memory.
5. Put necessary PII in a minimized request body, with schema-derived redaction and, where justified, application-layer field encryption.
6. Use fragments only for deliberately designed, isolated client-side bootstrap or split-knowledge protocols; remove them immediately, account for Performance Timeline retention, and prefer a new clean document before loading other code.
7. Never put credentials or raw PII in paths, query strings, referrers, tracing baggage, metric labels, or cache keys.
8. Never transmit a private cryptographic key merely to authenticate a request; use a proof of possession instead.

## Limits of these techniques

None of these techniques fully protects data that must be revealed to a compromised page. Same-origin malicious JavaScript can commonly read the value, intercept it before protection is applied, modify framework functions, or use the browser as an authenticated proxy.

The strongest architectures reduce how often the browser receives reusable secrets, reduce the authority and lifetime of every credential, prevent raw requests from reaching observability systems, and make unsafe data movement explicit rather than convenient.

## References

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/)
- [OWASP A02:2025 Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
- [OWASP A04:2025 Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
- [OWASP A06:2025 Insecure Design](https://owasp.org/Top10/2025/A06_2025-Insecure_Design/)
- [OWASP A07:2025 Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)
- [OWASP A09:2025 Security Logging and Alerting Failures](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/)
- [OWASP A10:2025 Mishandling of Exceptional Conditions](https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/)
- [OWASP A3:2017 Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)
- [OWASP REST Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html)
- [RFC 9111: HTTP Caching](https://www.rfc-editor.org/rfc/rfc9111.html)
- [RFC 6265: HTTP State Management Mechanism](https://www.rfc-editor.org/rfc/rfc6265.html)
- [RFC 6750: OAuth 2.0 Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750.html)
- [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html)
- [RFC 10017: OAuth 2.0 for Browser-Based Applications](https://www.rfc-editor.org/rfc/rfc10017.html)
- [RFC 7541: HPACK](https://www.rfc-editor.org/rfc/rfc7541.html)
- [RFC 9180: Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180.html)
- [RFC 9449: OAuth 2.0 Demonstrating Proof of Possession](https://www.rfc-editor.org/rfc/rfc9449.html)
- [W3C Referrer Policy](https://www.w3.org/TR/referrer-policy/)
- [W3C Navigation Timing](https://w3c.github.io/navigation-timing/)
- [W3C Resource Timing](https://w3c.github.io/resource-timing/)
- [W3C Performance Timeline](https://w3c.github.io/performance-timeline/)
- [WHATWG HTML history](https://html.spec.whatwg.org/dev/browsing-the-web.html#history)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OpenTelemetry HTTP semantic conventions](https://opentelemetry.io/docs/specs/semconv/registry/attributes/http/)
- [OpenTelemetry baggage security considerations](https://opentelemetry.io/docs/concepts/signals/baggage/#baggage-security-considerations)

// cysecurity.js - Cydog Browser Web Security Script
// https://github.com/Cydog-Browser/cy-security-js/
// Protects against XSS, CSP violations, certificate mismatches, and hides itself from hackers.

(function() {

    // ==========================================
    // SECTION 1: INPUT SANITIZATION
    // ==========================================
    const sanitizeInputs = () => {
        const sanitize = (value) => {
            return value.replace(/[<>"'&]/g, (match) => 
                ``
            );
        };

        document.addEventListener('input', (e) => {
            if (e.target.isContentEditable || 
                e.target.tagName === 'INPUT' || 
                e.target.tagName === 'TEXTAREA') {
                    if(e.target.type !== 'password' && e.target.getAttribute('data-sanitization') !== "disabled"){
                        e.target.value = sanitize(e.target.value);
                    }
            }
        });
    };

    // ==========================================
    // SECTION 2: DYNAMIC CSP MANAGEMENT
    // ==========================================
    const enforceCSP = () => {
        // Extract existing CSP from headers
        const cspHeader = document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content || '';
        let allowedDomains = new Set();

        // Parse CSP domains
        cspHeader.split(';').forEach(dir => {
            const [directive, ...sources] = dir.trim().split(/\s+/);
            if (directive.includes('src')) sources.forEach(src => allowedDomains.add(src));
        });

        // Create CSP meta tag if missing
        if (!cspHeader) {
            const meta = document.createElement('meta');
            meta.httpEquiv = "Content-Security-Policy";
            meta.setAttribute('content', `default-src 'self' https://${window.location.hostname};`);
            document.head.appendChild(meta);
        }

        // Intercept fetch requests
        const originalFetch = window.fetch;
        window.fetch = async (resource, options) => {
            var url;
            const response = await originalFetch(resource, options);
            const cspHeader = response.headers.get('Content-Security-Policy');
            //console.log(cspHeader);
            var isCSPHeaderSet = cspHeader != null ? true : false;
            const origin = window.location.origin;
            var pathname = window.location.pathname;
            const lastSlashIndex = pathname.lastIndexOf('/');
            if (lastSlashIndex !== -1 && lastSlashIndex < pathname.length - 1) {
                pathname = pathname.substring(0, lastSlashIndex + 1);
            }
            const absolutePath = origin + pathname;
            //console.log(absolutePath);
            var newResource = resource;
            if (typeof resource === 'string' && resource.startsWith('.') && !resource.startsWith('..')) {
                newResource = resource.replace('.', "");
            }
            //console.log(newResource);
            //console.log(absolutePath+newResource);
            if (typeof resource === 'string' && newResource.startsWith('/')){
                url = new URL(`${absolutePath}${newResource}`);
            } else if (typeof resource === 'string' && resource.startsWith('/')){
                url = new URL(`${absolutePath}${resource}`);
            } else if (typeof resource === 'string' && resource.startsWith('..')){
                url = new URL(`${absolutePath}${resource}`);
            } else if (typeof resource === 'string' && resource.startsWith('http')){
                url = new URL(resource);
            } else if(resource instanceof Request) {
                url = new URL(resource.url);
            } else {
                console.error("Invalid resource type provided to fetch request.");
            }
            
            // Block non-HTTPS requests
            if (url.protocol !== 'https:') {
                throw new Error(`Blocked insecure request to: ${url.href}`);
            }

            // Validate domain against CSP
            if (!allowedDomains.has(url.origin)) {
                if(isCSPHeaderSet && cspHeader.includes(url.origin)){
                    return;
                }
                console.warn(`CSP violation blocked: ${url.href}`);
                return Promise.reject(new Error("CSP violation"));
            }

            return originalFetch(resource, options);
        };
    };

    // ==========================================
    // SECTION 3: CERTIFICATE VALIDATION
    // ==========================================
    const validateCertificates = () => {
        const originalSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function(body) {
            this.addEventListener('readystatechange', function() {
                if (this.readyState === 4) {
                    const cert = this.getResponseHeader('ssl-cert');
                    const requestedDomain = new URL(this.responseURL).hostname;
                    console.log(requestedDomain);
                    if (cert && !cert.includes(requestedDomain)) {
                        console.error(`Certificate mismatch for ${requestedDomain}`);
                        this.dispatchEvent(new ErrorEvent('error'));
                    }
                }
            });
            originalSend.call(this, body);
        };
    };

    // ==========================================
    // SECTION 4: HIDE FROM HACKERS
    // ==========================================
    const hideFromHackers = () => {
        const self = document.getElementById('cysecurity');
        if (self) {
            self.remove();
        }
    }

    // ==========================================
    // INITIALIZATION
    // ==========================================
    enforceCSP();
    validateCertificates();
    sanitizeInputs();
    hideFromHackers();
})();

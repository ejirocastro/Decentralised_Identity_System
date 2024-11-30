;; Decentralized Identity System
;; A secure system for managing digital identities on Stacks blockchain

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-already-registered (err u101))
(define-constant err-not-registered (err u102))
(define-constant err-unauthorized (err u103))
(define-constant err-invalid-proof (err u104))
(define-constant err-expired (err u105))
(define-constant err-invalid-status (err u106))
(define-constant err-already-vouched (err u107))

;; Data Variables
(define-data-var next-id uint u1)
(define-data-var verification-threshold uint u3)  ;; Number of vouches needed for auto-verification
(define-data-var identity-expiration uint u52560) ;; Default expiration in blocks (approximately 1 year)

;; Data Maps
(define-map identities
    principal
    {
        id: uint,
        hash: (buff 32),           ;; Hash of personal data
        status: (string-ascii 20), ;; "pending", "verified", "suspended", or "expired"
        timestamp: uint,
        expiration: uint,          ;; Block height when identity expires
        verifier: (optional principal),
        trust-score: uint,         ;; Trust score from 0 to 100
        recovery-address: (optional principal)
    }
)

(define-map identity-attributes
    principal
    {
        name-hash: (buff 32),      
        email-hash: (buff 32),     
        additional-data: (buff 32),
        profile-image: (optional (buff 32)),
        social-links: (list 5 (buff 32)),
        credentials: (list 10 {credential-hash: (buff 32), issuer: principal, timestamp: uint})
    }
)

(define-map vouches
    { for-principal: principal, from-principal: principal }
    { timestamp: uint, weight: uint }
)

(define-map trusted-verifiers
    principal 
    { status: bool, weight: uint }
)

(define-map identity-claims
    principal
    (list 20 { claim-type: (string-ascii 30), claim-hash: (buff 32), timestamp: uint })
)

;; Private Functions
(define-private (is-contract-owner)
    (is-eq tx-sender contract-owner)
)

(define-private (get-current-time)
    block-height
)

(define-private (is-identity-expired (identity {id: uint, hash: (buff 32), status: (string-ascii 20), timestamp: uint, expiration: uint, verifier: (optional principal), trust-score: uint, recovery-address: (optional principal)}))
    (> (get-current-time) (get expiration identity))
)

;; (define-private (calculate-trust-score (user principal))
;;     (let (
;;         (vouch-count (len (get-vouches-for user)))
;;         (credential-count (len (default-to (list) (get credentials (default-to {name-hash: 0x00, email-hash: 0x00, additional-data: 0x00, profile-image: none, social-links: (list), credentials: (list)} (map-get? identity-attributes user))))))
;;     )
;;     (min u100 (+ (* vouch-count u10) (* credential-count u5)))
;;     )
;; )

;; Read-only Functions
(define-read-only (get-identity (user principal))
    (map-get? identities user)
)

(define-read-only (get-identity-attributes (user principal))
    (map-get? identity-attributes user)
)

(define-read-only (get-identity-claims (user principal))
    (map-get? identity-claims user)
)

(define-read-only (is-identity-verified (user principal))
    (match (map-get? identities user)
        identity (is-eq (get status identity) "verified")
        false
    )
)

(define-read-only (get-identity-count)
    (- (var-get next-id) u1)
)

(define-read-only (get-vouches-for (user principal))
    (filter (lambda (vouch) (is-eq (get for-principal vouch) user)) (map-values vouches))
)

(define-read-only (get-trust-score (user principal))
    (match (map-get? identities user)
        identity (get trust-score identity)
        u0
    )
)

(define-read-only (is-identity-active (user principal))
    (match (map-get? identities user)
        identity (and 
            (is-eq (get status identity) "verified")
            (not (is-identity-expired identity)))
        false
    )
)

(define-public (register-identity (data-hash (buff 32)) (attributes-data {name-hash: (buff 32), email-hash: (buff 32), additional-data: (buff 32), profile-image: (optional (buff 32)), social-links: (list 5 (buff 32)), credentials: (list 10 {credential-hash: (buff 32), issuer: principal, timestamp: uint})}))
    (let
        ((user-principal tx-sender))
        (asserts! (is-none (map-get? identities user-principal)) err-already-registered)
        
        (map-set identities
            user-principal
            {
                id: (var-get next-id),
                hash: data-hash,
                status: "pending",
                timestamp: (get-current-time),
                expiration: (+ (get-current-time) (var-get identity-expiration)),
                verifier: none,
                trust-score: u0,
                recovery-address: none
            }
        )
        
        (map-set identity-attributes
            user-principal
            attributes-data
        )
        
        (var-set next-id (+ (var-get next-id) u1))
        (ok true)
    )
)

(define-public (add-credential (credential-hash (buff 32)))
    (let (
        (user-principal tx-sender)
        (current-attributes (unwrap! (map-get? identity-attributes user-principal) err-not-registered))
        (new-credential {credential-hash: credential-hash, issuer: tx-sender, timestamp: (get-current-time)})
    )
    (ok (map-set identity-attributes
        user-principal
        (merge current-attributes 
            {credentials: (unwrap! (as-max-len? (append (get credentials current-attributes) new-credential) u10) err-unauthorized)})))
    )
)

(define-public (vouch-for-identity (user principal))
    (let (
        (vouching-principal tx-sender)
        (vouch-key { for-principal: user, from-principal: vouching-principal })
    )
        (asserts! (not (is-eq user vouching-principal)) err-unauthorized)
        (asserts! (is-none (map-get? vouches vouch-key)) err-already-vouched)
        (asserts! (is-some (map-get? identities vouching-principal)) err-unauthorized)
        
        (map-set vouches
            vouch-key
            { timestamp: (get-current-time), weight: u1 }
        )
        
        ;; Auto-verify if threshold reached
        (if (>= (len (get-vouches-for user)) (var-get verification-threshold))
            (verify-identity user "verified")
            (ok true)
        )
    )
)




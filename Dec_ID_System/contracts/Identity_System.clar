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


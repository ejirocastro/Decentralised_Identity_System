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

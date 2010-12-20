; vim:syntax=scheme expandtab
;;; Source this file if you want to start junkie's listener on port 29000.

(use-modules (ice-9 threads))

(if (not (defined? 'defs-loaded)) (load "defs.scm"))

;; Start a thread to listen for config command on port 29000

(make-thread start-repl-server 29000)


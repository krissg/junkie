; vim:syntax=scheme expandtab
;;; Source this file if you want to start junkie's SNMP subagent.
;;; Notice that you need the guile-agentx module installed.

(use-modules (ice-9 threads))

(if (not (defined? 'defs-loaded)) (load "defs.scm"))

;; Start SNMP subagent
(if have-snmp
  (begin (load "snmp-subagt.scm")
         (make-thread start-junkie-subagent))
  (display "Skip starting of junkie SNMP subagent.\n"))


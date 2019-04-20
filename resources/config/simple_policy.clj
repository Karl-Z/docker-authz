;;; Policies
;;;   :rules - a collection of rules to be groubed as one policy
;;;   :policies - a collection of policies to be groubed as one policy
;;;   :condition - flow control on policy validation
;;-----------------------------------------------------------------------------
;; Admin users can do whatever at any host
(defpolicy userAdmin
  :rules [(rule [:body "User"] #{"root" "ec2-user"})])

;; UserA can only manage HostA
(defpolicy userA_hstA
  :rules [(rule [:body "User"] #{"userA"})
          (rule [:body "Host"] #{"hstA"})])

;; UserB can only manage HostB
(defpolicy userB_hstB
  :rules [(rule [:body "User"] #{"userB"})
          (rule [:body "Host"] #{"hstB"})])

;; UserL can manage HostA, HostB
(defpolicy userL
  :rules [(rule [:body "User"] #{"userL"})
          (rule [:body "Host"] #{"hstA" "hstB"})])

;;; Set up runtime environment.
;;------------------------------------------------------------------------------

;; `*docker-api-version*' is the policy applied docker request version
(reset! *docker-api-versions* #{"1.26"})

;; `*default-add-policy-control*' is the the default policy control for add-policy
(reset! *default-add-policy-control* :sufficient)

;; set default authorization result to denial
(reset! *default-permission* false)

;;; Add policies to runtime.
;;; (add-policy description policy :context context :control control)
;;------------------------------------------------------------------------------
(add-policy "admin users rights" userAdmin)
(add-policy "userA at hstA" userA_hstA)
(add-policy "userB at hstB" userB_hstB)
(add-policy "userL" userL)


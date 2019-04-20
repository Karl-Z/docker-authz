;;; data source definitions
(defsource txtfile-api
  :type passwd
  :cache true
  :parameters {:path "docker-api.db"})


(defsource txtfile-users
  :type passwd
  :parameters {:path "users.db"})

(defsource txtfile-adminusers
  :type passwd
  :parameters {:path "admin-users.db"})

(defsource txtfile-usergroups
  :type group
  :parameters {:path "user-groups.db"})

(defsource txtfile-admingroups
  :type group
  :parameters {:path "admin-user-groups.db"})

(defsource txtfile-hosts
  :type passwd
  :parameters {:path "hosts.db"})

(defsource txtfile-hostgroups
  :type group
  :parameters {:path "host-groups.db"})

(defsource txtfile-deploymentenvironments
  :type group
  :parameters {:path "deployment-environments.db"})

(defsource txtfile-docker-api-write
  :type passwd
  :cache true
  :parameters {:path "docker-api-write.db"})

(defsource txtfile-docker-api-read
  :type passwd
  :cache true
  :parameters {:path "docker-api-read.db"})

(defsource txtfile-docker-api-delete
  :type passwd
  :cache true
  :parameters {:path "docker-api-delete.db"})

(defsource txtfile-docker-api-build
  :type passwd
  :cache true
  :parameters {:path "docker-api-build.db"})


;;; lookups
;; lookup function for user group identification
(deflookup usergroup-lookup
  :dominion [txtfile-usergroups]
  :return name->group)

;; given host name, look up host group 
(deflookup hostgroup-lookup
  :dominion [txtfile-hostgroups]
  :return name->group)

;; lookup deployment environment
(deflookup deploymentenvironment-lookup
  :dominion [txtfile-deploymentenvironments]
  :return name->group)

;; add callback function to the predefined hooks
(add-hook authz.wrap-usergroup/wrap-usergroup-hook usergroup-lookup)
(add-hook authz.wrap-hostgroup/wrap-hostgroup-hook hostgroup-lookup)
(add-hook authz.wrap-deploymentenvironment/wrap-deploymentenvironment-hook
          deploymentenvironment-lookup)


;;; Rule definitions.
;;----------------------------------------------------------------------------
;; validate one aspect of request
;;   :path - input value from the path of request, same as get-in
;;   :transform - a group of tuples of regexp and replacement
;;   :validator - call the function with input value or transformed input value
;;   :optional - ignore input and return true

(defrule valid-uri
  :path [:body "RequestUri"]
  :transform ["^/v\\d\\.\\d\\d" ""
              "/([^/?]+)[?/].*" "/$1"]
  :validator txtfile-api)

(defrule valid-user
  :path [:body "User"]
  :validator txtfile-users)

(defrule admin-user
  :path [:body "User"]
  :validator txtfile-adminusers)

(defrule valid-usergroup
  :path [:body "UserGroup"]
  :validator txtfile-usergroups)

(defrule admin-usergroup
  :path [:body "UserGroup"]
  :validator txtfile-admingroups)

(defrule valid-host
  :path [:body "Host"]
  :validator txtfile-hosts)

(defrule valid-hostgroup
  :path [:body "HostGroup"]
  :validator txtfile-hostgroups)

;; read operation
(defrule method-read
  :path [:body "RequestMethod"]
  :validator #{"GET"})

(defrule method-write
  :path [:body "RequestMethod"]
  :validator #{"POST" "PUT"})

(defrule method-delete
  :path [:body "RequestMethod"]
  :validator #{"DELETE"})

(defrule method-all
  :path [:body "RequestMethod"]
  :validator #{"GET" "POST" "PUT" "DELETE"})

(defrule allowed-images
  :path [:body "RequestBody" "Image"]
  :validator #{"busybox"})

(defrule have-labels
  :path [:body "RequestBody" "Labels"]
  :validator #(re-subset? % #{"com\\.company\\.user-.*"}))

;; (set %) - coerce to set in order to use subset?
(defrule drop-caps
  :path [:body "RequestBody" "HostConfig" "CapDrop"]
  :validator #(subset? #{"NET_BIND_SERVICE" "SETUID" "SETGID"} (set %)))

(defrule have-caps
  :path [:body "RequestBody" "HostConfig" "CapAdd"]
  :validator #(subset? #{"SYS_PTRACE"} (set %)))

;; used as context predictor
(defrule create-container
  :path [:body :params "containers"]
  :validator #{"create"})

(defrule allowed-network
  :path [:body "RequestBody" "HostConfig" "NetworkMode"]
  :type :optional
  :validator #{"bridge" "none"})

(defrule allowed-environments
  :path [:body "DeploymentEnvironment"]
  :validator #{"dev" "qa" "prod"})

(defrule denied-environments
  :path [:body "DeploymentEnvironment"]
  :validator #{"uat"})

(defrule allowed-mounts
  :path [:body "RequestBody" "HostConfig" "Mounts"]
  :validator #(re-subset? % #{".*=/opt" ".*=/var/log" ".*=/user/local"}))

(defrule allowed-volumes
  :path [:body "RequestBody" "HostConfig" "Volumes"]
  :validator #(re-subset? % #{"com\\.company\\.user-.*"}))


;;; Policies
;;;   :rules - a collection of rule to be groubed as one policy predictor
;;;   :policies - a collection of policies to be groubed as one policy
;;;   :condition - flow control on policy validation
;;-----------------------------------------------------------------------------
;; default policy to apply on all requests and responses
(defpolicy basic-policy
  :rules [valid-uri valid-user valid-host valid-hostgroup allowed-environments method-all])

(defpolicy act-read
  :rules [method-read
          (rule [:body "RequestUri"] txtfile-docker-api-read)])

(defpolicy act-write
  :rules [method-write
          (rule [:body "RequestUri"] txtfile-docker-api-write)])

(defpolicy act-delete
  :rules [method-delete
          (rule [:body "RequestUri"] txtfile-docker-api-delete)])

(defpolicy act-build
  :rules [method-write
          (rule [:body "RequestUri"] txtfile-docker-api-build)])

(defpolicy act-prune
  :condition :some
  :policies
  [(policy :all method-read
           (rule [:body "RequestUri"] #(re-matches #"/containers/json")))
   (policy :all method-read
           (rule [:body "RequestUri"] #(re-matches #"/images/json")))
   (policy :all method-write
           (rule [:body "RequestUri"] #(re-matches #"/images/prune")))])

(defpolicy role-operations
  :condition :some
  :policies [act-read act-write act-delete])

(defpolicy role-system
  :condition :some
  :policies [act-prune])

(defpolicy role-report
  :condition :some
  :policies [act-read])

(defpolicy userB
  :condition :all
  :rules [(rule [:body "User"] #{"userB"})
          (rule [:body "Host"] #{"HostTest"})]
  :policies [role-operations])

(defpolicy userL
  :condition :all
  :rules [(rule [:body "User"] #{"userL"})
          (rule [:body "HostGroup"] #{"HgrpIa" "HgrpIt" "HgrpId" "HgrpEp" "HgrpUt"})]
  :policies [role-operations])

(defpolicy groupC
  :rules [(rule [:body "UserGroup"] #{"groupC"})
          (rule [:body "HostGroup"] #{"HgrpIa" "HgrpIt" "HgrpId" "HgrpEp" "HgrpUt"})]
  :policies [role-report])

(defpolicy groupE
  :rules [(rule [:body "UserGroup"] #{"groupE"})
          (rule [:body "HostGroup"] #{"HgrpIa" "HgrpIt" "HgrpId" "HgrpEp" "HgrpUt"})]
  :policies [role-operations])

(defpolicy groupQ
  :condition :all
  :rules [(rule [:body "UserGroup"] #{"groupQ"})
          (rule [:body "HistGroup"] #{"HgrpIt" "HgrpId"})]
  :policies [role-operations])


;;; Set up runtime environment.
;;------------------------------------------------------------------------------

;; `*docker-api-versions*' are the default versions which policy applied to
(reset! *docker-api-versions* #{"1.26" "1.31"})

;; `*default-add-policy-control*' is the the default policy control for add-policy
(reset! *default-add-policy-control* :requisite)

;; set default to allow
(reset! *default-permission* false)

;;; Add policies to runtime.
;;; (add-policy description policy :context context :control control)
;;------------------------------------------------------------------------------

(add-policy "basic validation required" basic-policy)
(add-policy "only allow containers created from permitted images"
            (policy :all allowed-images)
            :context create-container)

(add-policy "caps restriction when creating container"
            (policy :all have-caps drop-caps)
            :context create-container)

;; Reset the default policy control to sufficient for afterwards added policies
(reset! *default-add-policy-control* :sufficient)
(add-policy "admin users sufficient"
            (policy :some admin-user admin-usergroup)
            :control :sufficient)

(add-policy "UsrL can prune"(policy :all
                  (rule [:body "User"] #{"usrL"})
                  (rule [:body "RequestUri"] #(re-matches #"/.*/prune$" %))
                  (rule [:body "HostGroup"] #{"hgrp1" "hgrp2"})))

(add-policy "UserB" userB)
(add-policy "UserL" userL)
(add-policy "GroupC" groupC)
(add-policy "GroupQ" groupQ)
(add-policy "GroupE" groupE)



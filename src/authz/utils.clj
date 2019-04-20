(ns authz.utils
  "Some useful functions and macros:
      re-subset?    - Is set1 a subset of set2 based on re-matches?
      do1           - just like do, but return the first form's value
      if-let*       - like if-let, also allow multi-bindings
      when-let*     - like when-let, also allow multi-bindings")

;; re-subset?: checking subset1 again subset2 which contains regexp that must
;;             match entry in subset1
(defn re-subset?
  "Is set1 a subset of set2 based on re-matches?
  Eg: (re-subset? #{\"aa\" \"bb\"} #{#\"a.\" #\"b.\"}) => true"
  [set1 set2]
  (every? true?
          (for [s1 set1]
            (some boolean
                  (for [s2 set2]
                    (re-matches (re-pattern s2) s1))))))


(defmacro do1
  ;; Copied from http://en.wikibooks.org/wiki/Clojure_Programming/Concepts.
  "Evaluates the expressions in order and returns the value of
  the first. If no expressions are supplied, returns nil."
  [first-form & other-forms]
  `(let [x# ~first-form]
     ~@other-forms
     x#))

;; if-let multiple bindings version
(defmacro if-let*
  ([bindings then]
   `(if-let* ~bindings ~then nil))
  ([bindings then else]
   (if (seq bindings)
     `(if-let [~(first bindings) ~(second bindings)]
        (if-let* ~(drop 2 bindings) ~then ~else)
        ~else)
     then)))

;; when-let multiple bindings version
(defmacro when-let*
  ([bindings & body]
   (if (seq bindings)
     `(when-let [~(first bindings) ~(second bindings)]
        (when-let* ~(drop 2 bindings) ~@body))
     `(do ~@body))))



(ns clj-emv.cvm
  "Cardholder Verification Methods"
  (:require [clj-emv.tags :as tags])
  (:require [clj-emv.utils :as utils])
  (:require [clojure.pprint :as pprint]))

(defn parse-cvm-list-tag[cvm-list-tag currency-code-tag]
  (defn loop-cv-rules[rules rule-bytes]
    (if (not (empty? rule-bytes))
        (let [cv-rule (apply tags/cvm-list-from-bytes (take 2 rule-bytes))]
          (loop-cv-rules (cons cv-rule rules) (drop 2 rule-bytes)))
        rules))

  (defn cvm-amount-to-decimal[amount-bytes]
    (/ (bigdec (utils/bytes-to-hex-string amount-bytes)) 100))

  (let [cvm-list-bytes (:value cvm-list-tag)
        cvm-x-bytes (take 4 cvm-list-bytes)
        cvm-y-bytes (take 4 (drop 4 cvm-list-bytes))
        x (cvm-amount-to-decimal cvm-x-bytes)
        y (cvm-amount-to-decimal cvm-y-bytes)

        cv-rule-bytes (drop 8 cvm-list-bytes)
        rules (loop-cv-rules '() cv-rule-bytes)

        currency-code (utils/bytes-to-hex-string (:value currency-code-tag))]
    {:x x
     :y y
     :rules rules
     :currency-code currency-code}))

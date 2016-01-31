(ns clj-emv.action-analysis
  "Terminal Action Analysis"
  (:require [clojure.pprint :as pprint])
  (:require [clj-emv.bit-ops :as bit-ops])
  (:require [clj-emv.utils :as utils])
  (:require [clj-emv.terminal :as terminal])
  (:require [clj-emv.tags :as tags]))

(defn generate-ac-p1[ac-type is-cda-requested]
  (let [base (bit-shift-left (condp = ac-type
                              :aac 0
                              :tc 1
                              :arqc 2
                              2)
                             6)
        cda (if is-cda-requested (bit-ops/bit-on-at 5) 0)]
    (+ base cda)))

(defn- get-cdol-object-value[tag-number length transaction-details]
  (let [zeros (vec (repeat length 0x00))
        terminal-resident-value (terminal/terminal-resident-tags tag-number)
        transaction-specific-value (transaction-details tag-number)
        bytes (first (filter (complement nil?) [transaction-specific-value terminal-resident-value zeros]))]
    bytes))

(defn generate-ac-data[cdol1-tag dynamic-number-response transaction-details]
  ; TODO: combine with the PDOL generation functions
  (defn create-cdol-bytes[cdol-tags]
    (defn- loop-cdol-tags[bytes tags]
      (if (empty? tags)
        bytes
        (let [tag (first tags)
              tail-tags (rest tags)
              tag-bytes (get-cdol-object-value (:tag-number tag) (:object-length tag) transaction-details)]
          (loop-cdol-tags (concat bytes tag-bytes) tail-tags))))
    (loop-cdol-tags [] cdol-tags))

  (let [cdol-tags (tags/get-dol-tags (:value cdol1-tag))
        cdol-bytes (create-cdol-bytes cdol-tags)]
    cdol-bytes))

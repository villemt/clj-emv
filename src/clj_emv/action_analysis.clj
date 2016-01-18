(ns clj-emv.action-analysis
  "Terminal Action Analysis"
  (:require [clojure.pprint :as pprint])
  (:require [clj-emv.bit-ops :as bit-ops])
  (:require [clj-emv.utils :as utils])
  (:require [clj-emv.tags :as tags]))

(defn- generate-ac-p1[ac-type is-cda-requested]
  (let [base (bit-shift-left (condp = ac-type
                              :aac 0
                              :tc 1
                              :arqc 2
                              2)
                             6)
        cda (if is-cda-requested (bit-ops/bit-on-at 5) 0)]
    (+ base cda)))

(defn print-dol-tag[dol-tag-info]
  (let [tag-number (:tag-number dol-tag-info)
        tag-name (:name (:tag-info dol-tag-info))
        object-length (:object-length dol-tag-info)]
  (println " -> Tag (hex):\t" (utils/hexify tag-number) tag-name)
  (println "    Length:\t" object-length)))

(defn generate-ac-data[cdol1-tag]
  (println "\nCard Risk Management Data Object List 1 (CDOL1):")
  (println (tags/tag-value-as-hex-string cdol1-tag) "\n")
  (dorun (map print-dol-tag (tags/get-dol-tags (:value cdol1-tag))))

  ; TODO: Populate the CDOL1 fields and generate AC

  )

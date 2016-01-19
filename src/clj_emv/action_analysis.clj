(ns clj-emv.action-analysis
  "Terminal Action Analysis"
  (:require [clojure.pprint :as pprint])
  (:require [clj-emv.bit-ops :as bit-ops])
  (:require [clj-emv.utils :as utils])
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

(defn generate-ac-data[cdol1-tag dynamic-number-response]

  ; TODO: Populate the CDOL1 fields and generate AC

  ; Hard-coded CDOL1 generation, based on the following information
  ;9F02 06  0x000000000001
  ;9F03 06  0x000000000000
  ;9F1A 02  0x00F6 (Finland)
  ;95   05  0x0000000000
  ;5F2A 02  0x03D2 (EUR)
  ;9A   03  0x160119
  ;9C   01  0x21
  ;9F37 04  0x11200211, e.g. random-numbers (repeatedly 4 #(rand-int 255))
  ;9F35 01  0x11
  ;9F45 02  0x0000
  ;9F4C 08  (challenge)
  ;9F34 03  0x000000
  ;9F21 03  0x213800
  ;9F7C 14  0x0000000000000000000000000000000000000000

  (let [first-bytes (vec (utils/parse-hex-string "00000000000100000000000000F6000000000003D21601192111200211110000"))
        challenge-bytes (:data dynamic-number-response)
        last-bytes (vec (utils/parse-hex-string "0000002138000000000000000000000000000000000000000000"))
        all-bytes (concat first-bytes challenge-bytes last-bytes)]
    all-bytes))

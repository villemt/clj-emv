(ns clj-emv.core-test
  (:use clj-emv.pcsc)
  (:use clj-emv.bit-ops)
  (:use clj-emv.crypto)
  (:use clj-emv.utils)
  (:use clj-emv.tags)
  (:use clj-emv.file)
  (:use clj-emv.date)
  (:use clj-emv.sda)
  (:use clj-emv.dda)
  (:require [clojure.test :refer :all]
            [clj-emv.core :refer :all]))

;; TODO: Proper test setup

(deftest tag-parsing-test
  (testing "tag classes"
    (is (tag-class 2r00000000) :universal)
    (is (tag-class 2r01000000) :application)
    (is (tag-class 2r10000000) :context-specific)
    (is (tag-class 2r11000000) :private))

   (testing "primitive and constructured "
    (tag-is-constructed? 2r00000000)
    (not (tag-is-constructed? 2r00100000)))

   (testing "second value byte "
    (tag-has-second-value-byte? 2r00011111)
    (not (tag-is-constructed? 2r00000000)))

   (testing "tag value"
    (is (tag-value 2r00110000) 2r100000))

   (testing "counting length bytes"
    (is (tag-length-bytes-count 2r00000000) 1)
    (is (tag-length-bytes-count 2r10000001) 2)
    (is (tag-length-bytes-count 2r10000010) 3))

   (testing "tag length"
    (is (tag-length-bytes-value [2r00011010]) 26)
    (is (tag-length-bytes-value [2r10000001  2r11000000]) 192))

   (testing "status byte coding"
    (is (= (:status (status-bytes-to-description 0x90 0x00)) "Process completed")))

   (testing "parsing full tlv, single bytes only"
    (is (= (parse-tlv-bytes (parse-hex-string "6F1A84")))
      {:tag 0x6F
       :class :application
       :is-constructed false
       :length 26
       :value (parse-hex-string "84")
       :tail ()}))

   (testing "parsing AIP bytes"
    (let [aip (aip-from-bytes 2r01000000 0x00)]
      (is (= (and (:sda-supported aip) (not (:cda-supported aip)))))))

    (testing "bit operations"
      (let [mask 2r00111111
            byte1 2r10001001
            byte2 2r11001001]
        (is (equals-masked mask byte1 byte2)))))

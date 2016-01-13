(ns clj-emv.crypto
  "Cryptographic functions required for EMV"
  (:use clj-emv.bit-ops)
  (:require [clj-emv.utils :as utils]))

(defn sha1[bytes]
  (vec (map unsigned (seq (.digest (java.security.MessageDigest/getInstance "sha1") (byte-array bytes))))))

(defn modularExp[base exponent modulus]
  (defn modulus-fn[a b]
    (mod (* a b) modulus))

  (loop [b base
         e exponent
         x 1]
    (if (zero? e) x
      (if (even? e)
        (recur (modulus-fn b b) (/ e 2) x)
        (recur (modulus-fn b b) (quot e 2) (modulus-fn b x))))))

(defn recover[certificate-bytes exponent modulus-bytes]
  (let [certificate (utils/bytes-to-num certificate-bytes)
        modulus (utils/bytes-to-num modulus-bytes)
        result (modularExp certificate exponent modulus)
        hex-string (format "%X" (biginteger result))] ;; FIX
    (vec (utils/parse-hex-string hex-string))))

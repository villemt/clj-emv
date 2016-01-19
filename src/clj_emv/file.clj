(ns clj-emv.file
  "Utils for reading text files"
  (:use clj-emv.utils)
  (:require [clojure.string :as str])
  (:require [clojure.java.io :as io]))

(defn get-lines [file]
  (str/split-lines (slurp file)))

(defn split-lines[lines]
  (map #(str/split % #";") lines))

(defn find-key[key-index rid]
  (defn find-key[lines key-index rid]
    (let [value (first (filter #(and (= (nth % 2) (str (read-string key-index))) (= (nth % 3) rid)) lines))]
      {
        :issuer (nth value 0)
        :exponent (hex-to-num (nth value 1))
        :index (nth value 2)
        :rid (vec (parse-hex-string (nth value 3)))
        :nca (/ (count (nth value 4)) 2)
        :modulus (vec (parse-hex-string (nth value 4)))
        ;:modulus (hex-to-num (nth value 4))
        ;:modulus-length (count (nth value 4))
        :length (read-string (nth value 5))
        :sha1 (vec (parse-hex-string (nth value 6)))
        :type (nth value 7)
      }))
  (let [lines (split-lines (get-lines (io/resource "keys.csv")))]
    (find-key lines (hexify key-index) (hexify-list rid))))

(defn find-tag-info[tag]
  (defn lines-find-tag[lines tag]
    (let [value (first (filter #(= (first %) (hexify tag)) lines))]
      {
        :tag (nth value 0)
        :name (nth value 1)
        :description (nth value 2)
        :source (nth value 3)
        :format (nth value 4)
        ;:template (nth value 5)
        ;:min-length (nth value 6)
        ;:max-length (nth value 7)
        ;:type (nth value 8)
        ;:example (nth value 9)
      }))

  (let [lines (split-lines (get-lines (io/resource "tags.csv")))]
    (lines-find-tag lines tag)))

(defn find-country[code]
  (let [trimmed-code (str/replace-first code #"0+" "")
        lines (split-lines (get-lines (io/resource "countries.csv")))]
    (second (first (filter #(= (first %) trimmed-code) lines)))))

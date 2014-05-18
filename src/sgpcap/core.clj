(ns sgpcap.core
    (:require 
      clojure.pprint
      [clojure.string :as string]
    )
    (:use 
      clojure.java.io
      clojure.core
      gloss.core
      gloss.io
      ) 
    (:gen-class))

;; For repl (use 'sgpcap.core :reload-all)

;;clj-net-pcap.core clj-net-pcap.native clj-net-pcap.pcap-data clj-assorted-utils.util
     
(def pfile "/tmp/session1.pcap")

;; Pcap global header
;typedef struct pcap_hdr_s {
;        guint32 magic_number;   /* magic number */
;        guint16 version_major;  /* major version number */
;        guint16 version_minor;  /* minor version number */
;        gint32  thiszone;       /* GMT to local correction */
;        guint32 sigfigs;        /* accuracy of timestamps */
;        guint32 snaplen;        /* max length of captured packets, in octets */
;        guint32 network;        /* data link type */
;} pcap_hdr_t;
; typedef struct pcaprec_hdr_s {
;        guint32 ts_sec;         /* timestamp seconds */
;        guint32 ts_usec;        /* timestamp microseconds */
;        guint32 incl_len;       /* number of octets of packet saved in file */
;        guint32 orig_len;       /* actual length of packet */
;} pcaprec_hdr_t;

(def pcap-hdr-sz (/ (+ 32 16 16 32 32 32 32) 8))

(def pcap-hdr-fr (compile-frame {
  :magic_number   :uint32, 
  :version_major  :uint16,
  :version_minor  :uint16,
  :thiszone       :uint32,
  :sigfigs        :uint32,
  :snaplen        :uint32,
  :network        :uint32 }))

(def pcaprec-hdr-sz (/ (+ 32 32 32 32) 8))

(def pcaprec-hdr-fr (compile-frame {
  :ts_sec       :uint32,
  :ts_usec      :uint32,
  :incl_len     :uint32,
  :orig_len     :uint32 }))

(defn parse-pcap-hdr [buffer]
  (decode pcap-hdr-fr buffer))

(defn read-pcap-hdr [in]
  (let [buffer (byte-array pcap-hdr-sz)]
    (.read in buffer)
    (parse-pcap-hdr buffer)))

(defn parse-pcaprec-hdr [buffer]
  (println "Rec Buffer len: " (byte-count buffer))
  (decode pcaprec-hdr-fr buffer))

(defn read-pcaprec-hdr [fname]
  (let [buffer (byte-array pcap-hdr-sz)]
    (.read (input-stream pfile) buffer)
    (parse-pcaprec-hdr buffer)))

(defn read-pcap-file [fname]
  (with-open [in (input-stream fname)]
    (let [hdr (read-pcap-hdr in)]
      (pprint hdr))))

(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (println pfile))


package com.memscan.app

object NativeScanner {
    init { System.loadLibrary("scanner") }

    @JvmStatic external fun probe(pid: Int): String
    @JvmStatic external fun firstScan(pid: Int, type: Int, value: String): Long
    @JvmStatic external fun nextScan(pid: Int, type: Int, value: String): Long
    @JvmStatic external fun results(max: Int): LongArray
    @JvmStatic external fun readValue(pid: Int, addr: Long, type: Int): String?
    @JvmStatic external fun writeValue(pid: Int, addr: Long, type: Int, value: String): Long
    @JvmStatic external fun strerror(code: Int): String
}

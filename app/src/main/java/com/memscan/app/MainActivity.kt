package com.memscan.app

import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle
import android.widget.*
import java.io.File
import java.util.concurrent.ConcurrentHashMap

data class Proc(val pid: Int, val name: String, val uid: Int, val mine: Boolean, val exe: String) {
    override fun toString() = (if (mine) "★ " else "") + "$pid  uid=$uid  $name  [$exe]"
}

class MainActivity : Activity() {
    private lateinit var procSpinner: Spinner
    private lateinit var typeSpinner: Spinner
    private lateinit var valueInput: EditText
    private lateinit var status: TextView
    private lateinit var list: ListView
    private val types = listOf("Int32", "Int64", "Float", "Double")
    private var shown = listOf<Long>()
    private val frozen = ConcurrentHashMap<Long, String>()   // addr -> "tipo|valor"
    @Volatile private var frozenPid = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
            fitsSystemWindows = true
        }
        procSpinner = Spinner(this)
        typeSpinner = Spinner(this).apply {
            adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, types)
        }
        valueInput = EditText(this).apply { hint = "Valor"; setSingleLine() }
        status = TextView(this).apply { text = "Toque em Atualizar processos." }
        list = ListView(this)

        root.addView(button("Atualizar processos") { refreshProcs() })
        root.addView(procSpinner)
        root.addView(button("Testar acesso à memória") { probe() })
        root.addView(button("Ver arquivos carregados") { modules() })
        root.addView(typeSpinner)
        root.addView(valueInput)
        val row = LinearLayout(this)
        row.addView(button("Primeira busca") { scan(true) }, LinearLayout.LayoutParams(0, -2, 1f))
        row.addView(button("Busca seguinte") { scan(false) }, LinearLayout.LayoutParams(0, -2, 1f))
        root.addView(row)
        root.addView(button("Descongelar tudo") { frozen.clear(); toast("Descongelado") })
        root.addView(status)
        root.addView(list, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(root)

        list.setOnItemClickListener { _, _, i, _ -> editDialog(shown[i]) }

        Thread {
            while (true) {
                try {
                    val pid = frozenPid
                    if (pid != 0) for ((a, tv) in frozen) {
                        val p = tv.split("|", limit = 2)
                        NativeScanner.writeValue(pid, a, p[0].toInt(), p[1])
                    }
                    Thread.sleep(50)
                } catch (_: Exception) {}
            }
        }.apply { isDaemon = true; start() }

        refreshProcs()
    }

    private fun button(t: String, f: () -> Unit) = Button(this).apply {
        text = t; isAllCaps = false; setOnClickListener { f() }
    }
    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_SHORT).show()
    private fun bg(f: () -> Unit) = Thread { f() }.start()
    private fun ui(f: () -> Unit) = runOnUiThread { f() }
    private fun pid(): Int? = (procSpinner.selectedItem as? Proc)?.pid
    private fun type() = typeSpinner.selectedItemPosition

    private fun refreshProcs() {
        // O clonador falsifica Process.myUid(); o UID real vem do kernel
        val me = try {
            File("/proc/self/status").useLines { ls ->
                ls.firstOrNull { it.startsWith("Uid:") }
                    ?.split(Regex("\\s+"))?.getOrNull(1)?.toIntOrNull()
            }
        } catch (_: Exception) { null } ?: android.os.Process.myUid()
        val myPid = try { File("/proc/self").canonicalFile.name.toInt() }
            catch (_: Exception) { android.os.Process.myPid() }
        val out = mutableListOf<Proc>()
        var total = 0
        var unreadable = 0
        File("/proc").listFiles()?.forEach { d ->
            val p = d.name.toIntOrNull() ?: return@forEach
            total++
            try {
                val uid = File("/proc/$p/status").useLines { ls ->
                    ls.firstOrNull { it.startsWith("Uid:") }
                        ?.split(Regex("\\s+"))?.getOrNull(1)?.toIntOrNull()
                } ?: -1
                val name = try {
                    File("/proc/$p/cmdline").readText().substringBefore('\u0000')
                } catch (_: Exception) { "" }
                val exe = try { File("/proc/$p/exe").canonicalPath.substringAfterLast('/') }
                    catch (_: Exception) { "?" }
                val label = if (p == myPid) "(MemScan) $name" else name
                out += Proc(p, label.ifEmpty { "?" }, uid, uid == me, exe)
            } catch (_: Exception) { unreadable++ }
        }
        out.sortWith(compareByDescending<Proc> { it.mine }.thenBy { it.pid })
        procSpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, out)
        status.text = "Meu UID: $me | PID: $myPid\n" +
            "Entradas em /proc: $total | ilegíveis: $unreadable\n" +
            "Listados: ${out.size} | com meu UID (★): ${out.count { it.mine }}"
    }

    private fun modules() {
        val p = pid() ?: return toast("Escolha um processo")
        bg {
            val skip = listOf("/system", "/apex", "/vendor", "/dev", "/proc", "/product", "/odm")
            val txt = try {
                File("/proc/$p/maps").readLines()
                    .mapNotNull { l -> val i = l.indexOf('/'); if (i < 0) null else l.substring(i).trim() }
                    .filter { f -> skip.none { f.startsWith(it) } }
                    .distinct().take(60).joinToString("\n")
            } catch (e: Exception) { "Erro: ${e.message}" }
            ui {
                AlertDialog.Builder(this)
                    .setTitle("Arquivos carregados (pid $p)")
                    .setMessage(txt.ifEmpty { "(nada além do sistema)" })
                    .setPositiveButton("OK", null)
                    .show()
            }
        }
    }

    private fun probe() {
        val p = pid() ?: return toast("Escolha um processo")
        status.text = "Testando..."
        bg { val r = NativeScanner.probe(p); ui { status.text = r } }
    }

    private fun scan(first: Boolean) {
        val p = pid() ?: return toast("Escolha um processo")
        val v = valueInput.text.toString().trim()
        if (v.isEmpty()) return toast("Digite o valor")
        val t = type()
        status.text = "Buscando..."
        bg {
            val r = if (first) NativeScanner.firstScan(p, t, v) else NativeScanner.nextScan(p, t, v)
            if (r < 0) {
                ui { status.text = "Erro: " + NativeScanner.strerror((-r).toInt()) }
            } else {
                val addrs = NativeScanner.results(100)
                val rows = addrs.map { "0x%X = %s".format(it, NativeScanner.readValue(p, it, t) ?: "?") }
                ui {
                    shown = addrs.toList()
                    status.text = "$r resultados" + if (r > 100) " (mostrando 100)" else ""
                    list.adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, rows)
                }
            }
        }
    }

    private fun editDialog(addr: Long) {
        val p = pid() ?: return
        val t = type()
        val input = EditText(this).apply { hint = "Novo valor"; setSingleLine() }
        AlertDialog.Builder(this)
            .setTitle("0x%X".format(addr))
            .setView(input)
            .setPositiveButton("Gravar") { _, _ ->
                val v = input.text.toString().trim()
                bg {
                    val r = NativeScanner.writeValue(p, addr, t, v)
                    ui { toast(if (r > 0) "Gravado" else "Erro: " + NativeScanner.strerror((-r).toInt())) }
                }
            }
            .setNeutralButton("Congelar") { _, _ ->
                val v = input.text.toString().trim()
                if (v.isNotEmpty()) { frozenPid = p; frozen[addr] = "$t|$v"; toast("Congelado") }
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }
}

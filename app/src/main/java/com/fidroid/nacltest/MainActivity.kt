package com.fidroid.nacltest

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import java.nio.charset.Charset

private const val TAG = "MainActivity"

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val keyPair = NaclUtils.generateKeyPair()

        val keyPair2 = NaclUtils.generateKeyPair()

        findViewById<TextView>(R.id.tvPublicKey).text = keyPair.publicKey.toString();
        findViewById<TextView>(R.id.tvPrivateKey).text = keyPair.privateKey.toString();
        val editText = findViewById<EditText>(R.id.editText)
        val tvEncryptedText = findViewById<TextView>(R.id.tvEncryptedText)
        val tvDecryptedText = findViewById<TextView>(R.id.tvDecryptedText)

        val pk = keyPair.publicKey.toBytes()
        val prik = keyPair.privateKey.toBytes()

        val pk2 = keyPair2.publicKey.toBytes()
        val prik2 = keyPair2.privateKey.toBytes()

        findViewById<Button>(R.id.btnEncrypt).setOnClickListener {
            tvEncryptedText.text = Base64.encodeToString(NaclUtils.encrypt(editText.text.toString().toByteArray(Charset.defaultCharset()), pk, prik2), Base64.NO_WRAP)
        }
        findViewById<Button>(R.id.btnDecrypt).setOnClickListener {
            NaclUtils.decrypt(Base64.decode(tvEncryptedText.text.toString(), Base64.NO_WRAP), pk2, prik)?.let {
                tvDecryptedText.text = String(it)
            }
        }
    }
}
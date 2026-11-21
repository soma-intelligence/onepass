package me.somalabs.onepass

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Debug builds only: a plain login form in another task, to drive OnePass
 * AutoFill on the emulator (fill, save prompt). `adb shell am start -n
 * me.somalabs.onepass/.LoginDemoActivity`. The service fills it as the app
 * "me.somalabs.onepass" (OnePass's other screens are never filled).
 */
class LoginDemoActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(48, 160, 48, 48) }
        col.addView(TextView(this).apply { text = "Demo login"; textSize = 24f })
        col.addView(EditText(this).apply {
            hint = "Username"; inputType = InputType.TYPE_CLASS_TEXT
            setAutofillHints(View.AUTOFILL_HINT_USERNAME)
        })
        col.addView(EditText(this).apply {
            hint = "Password"; inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setAutofillHints(View.AUTOFILL_HINT_PASSWORD)
        })
        col.addView(Button(this).apply { text = "Sign in"; setOnClickListener { finish() } })
        setContentView(col)
    }
}

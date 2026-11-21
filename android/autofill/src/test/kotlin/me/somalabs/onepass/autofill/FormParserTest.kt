package me.somalabs.onepass.autofill

import android.text.InputType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class FormParserTest {
    private val text = InputType.TYPE_CLASS_TEXT
    private val password = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
    private val email = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS

    @Test
    fun autofillHintsComeFirst() {
        assertEquals(Role.PASSWORD, FormParser.classify(Clue(hints = listOf("password"), inputType = text)))
        assertEquals(Role.USERNAME, FormParser.classify(Clue(hints = listOf("username"), inputType = password)))
        assertEquals(Role.USERNAME, FormParser.classify(Clue(hints = listOf("emailAddress"))))
        assertEquals(Role.OTP, FormParser.classify(Clue(hints = listOf("smsOTPCode"))))
    }

    @Test
    fun htmlInputs() {
        assertEquals(Role.PASSWORD, FormParser.classify(Clue(htmlTag = "input", htmlType = "password", htmlName = "pwd")))
        assertEquals(Role.NEW_PASSWORD, FormParser.classify(Clue(htmlTag = "input", htmlType = "password", htmlName = "new_password")))
        assertEquals(Role.USERNAME, FormParser.classify(Clue(htmlTag = "input", htmlType = "email")))
        assertEquals(Role.USERNAME, FormParser.classify(Clue(htmlTag = "input", htmlType = "text", htmlName = "login")))
        assertEquals(Role.OTP, FormParser.classify(Clue(htmlTag = "input", htmlType = "text", htmlAutocomplete = "one-time-code")))
        assertEquals(Role.OTHER, FormParser.classify(Clue(htmlTag = "input", htmlType = "search", htmlName = "q")))
    }

    @Test
    fun inputTypesAndNames() {
        assertEquals(Role.PASSWORD, FormParser.classify(Clue(inputType = password, idEntry = "pin_field")))
        assertEquals(Role.USERNAME, FormParser.classify(Clue(inputType = email)))
        assertEquals(Role.USERNAME, FormParser.classify(Clue(inputType = text, idEntry = "username")))
        assertEquals(Role.USERNAME, FormParser.classify(Clue(inputType = text, hint = "Identifiant")))
        assertEquals(Role.PASSWORD, FormParser.classify(Clue(inputType = text, hint = "Mot de passe")))
        assertEquals(Role.OTHER, FormParser.classify(Clue(inputType = text, idEntry = "search_box", hint = "Search users")))
        assertEquals(Role.OTHER, FormParser.classify(Clue(inputType = text, idEntry = "comment")))
    }
}

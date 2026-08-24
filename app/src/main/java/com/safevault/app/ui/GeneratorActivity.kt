package com.safevault.app.ui

import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.core.view.isVisible
import com.google.android.material.slider.Slider
import com.safevault.app.R
import com.safevault.app.databinding.ActivityGeneratorBinding
import kotlin.math.roundToInt

/**
 * The standalone generator surface from PRD section 5.
 *
 * History is deliberately session-only: it lives in this activity and dies with
 * it, is never written to the database, and is dropped the moment the vault
 * locks. A generator that persisted its output would quietly become a second,
 * unencrypted copy of the passwords the vault exists to protect.
 */
class GeneratorActivity : SecureActivity() {

    private lateinit var binding: ActivityGeneratorBinding
    private lateinit var passphrases: PassphraseGenerator

    private val history = ArrayDeque<String>()
    private var current: String = ""

    companion object {
        private const val HISTORY_LIMIT = 8
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (isFinishing) return

        binding = ActivityGeneratorBinding.inflate(layoutInflater)
        setContentView(binding.root)
        passphrases = PassphraseGenerator.load(this)

        binding.toolbar.setNavigationOnClickListener { finish() }

        binding.modeToggle.addOnButtonCheckedListener { _, _, isChecked ->
            if (isChecked) {
                applyMode()
                regenerate()
            }
        }

        setUpPasswordControls()
        setUpPassphraseControls()

        binding.btnRegenerate.setOnClickListener { regenerate() }
        binding.btnCopy.setOnClickListener { copyCurrent() }

        binding.modeToggle.check(R.id.modePassword)
        applyMode()
        regenerate()
    }

    // ── Controls ───────────────────────────────────────────────────────────

    private fun setUpPasswordControls() {
        binding.lengthSlider.valueFrom = PasswordGenerator.MIN_LENGTH.toFloat()
        binding.lengthSlider.valueTo = PasswordGenerator.MAX_LENGTH.toFloat()
        binding.lengthSlider.value = PasswordGenerator.DEFAULT_LENGTH.toFloat()
        binding.lengthSlider.addOnChangeListener(onSliderChange)

        listOf(binding.cbLower, binding.cbUpper, binding.cbDigits, binding.cbSymbols)
            .forEach { box ->
                box.setOnCheckedChangeListener { _, _ ->
                    // Turning off the last class would leave nothing to sample from.
                    if (!passwordOptions().isUsable) {
                        box.isChecked = true
                        Toast.makeText(this, R.string.generator_need_one_class, Toast.LENGTH_SHORT)
                            .show()
                        return@setOnCheckedChangeListener
                    }
                    regenerate()
                }
            }
    }

    private fun setUpPassphraseControls() {
        binding.wordsSlider.valueFrom = PassphraseGenerator.MIN_WORDS.toFloat()
        binding.wordsSlider.valueTo = PassphraseGenerator.MAX_WORDS.toFloat()
        binding.wordsSlider.value = PassphraseGenerator.DEFAULT_WORD_COUNT.toFloat()
        binding.wordsSlider.addOnChangeListener(onSliderChange)

        binding.separatorPicker.setAdapter(
            ArrayAdapter(
                this,
                android.R.layout.simple_list_item_1,
                PassphraseGenerator.SEPARATORS.map(::separatorLabel)
            )
        )
        binding.separatorPicker.setText(separatorLabel(PassphraseGenerator.SEPARATORS.first()), false)
        binding.separatorPicker.setOnItemClickListener { _, _, _, _ -> regenerate() }

        binding.cbCapitalize.setOnCheckedChangeListener { _, _ -> regenerate() }
        binding.cbNumber.setOnCheckedChangeListener { _, _ -> regenerate() }
    }

    private val onSliderChange = Slider.OnChangeListener { _, _, fromUser ->
        if (fromUser) regenerate()
    }

    private fun applyMode() {
        val passwordMode = isPasswordMode()
        binding.passwordControls.isVisible = passwordMode
        binding.passphraseControls.isVisible = !passwordMode
    }

    private fun isPasswordMode() = binding.modeToggle.checkedButtonId == R.id.modePassword

    // ── Generation ─────────────────────────────────────────────────────────

    private fun passwordOptions() = PasswordGenerator.Options(
        length = binding.lengthSlider.value.roundToInt(),
        lowercase = binding.cbLower.isChecked,
        uppercase = binding.cbUpper.isChecked,
        digits = binding.cbDigits.isChecked,
        symbols = binding.cbSymbols.isChecked
    )

    private fun passphraseOptions() = PassphraseGenerator.Options(
        words = binding.wordsSlider.value.roundToInt(),
        separator = selectedSeparator(),
        capitalize = binding.cbCapitalize.isChecked,
        appendNumber = binding.cbNumber.isChecked
    )

    private fun regenerate() {
        if (current.isNotEmpty()) {
            history.addFirst(current)
            while (history.size > HISTORY_LIMIT) history.removeLast()
        }

        val bits: Double
        if (isPasswordMode()) {
            val options = passwordOptions()
            current = PasswordGenerator.generate(options)
            bits = PasswordGenerator.entropyBits(options)
            binding.lengthLabel.text = getString(R.string.generator_length, options.length)
        } else {
            val options = passphraseOptions()
            current = passphrases.generate(options)
            bits = passphrases.entropyBits(options)
            binding.wordsLabel.text = getString(R.string.generator_words, options.words)
        }

        binding.tvOutput.text = current
        binding.tvEntropy.text = getString(R.string.generator_entropy, bits.roundToInt())
        renderHistory()
    }

    private fun renderHistory() {
        binding.historySection.isVisible = history.isNotEmpty()
        binding.tvHistory.text = history.joinToString("\n")
        binding.tvHistoryNote.setText(R.string.generator_history_note)
    }

    private fun copyCurrent() {
        if (SecureClipboard.copySensitive(this, getString(R.string.generated_secret), current)) {
            Toast.makeText(
                this,
                getString(R.string.copied_autoclear, SecureClipboard.CLEAR_DELAY_MS / 1000),
                Toast.LENGTH_SHORT
            ).show()
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    private fun selectedSeparator(): String {
        val label = binding.separatorPicker.text?.toString().orEmpty()
        return PassphraseGenerator.SEPARATORS.firstOrNull { separatorLabel(it) == label }
            ?: PassphraseGenerator.SEPARATORS.first()
    }

    private fun separatorLabel(separator: String) = when (separator) {
        " " -> getString(R.string.separator_space)
        "-" -> getString(R.string.separator_hyphen)
        "." -> getString(R.string.separator_dot)
        "_" -> getString(R.string.separator_underscore)
        else -> separator
    }

    override fun onDestroy() {
        super.onDestroy()
        // Nothing here is persisted, but do not leave it sitting in a live heap
        // any longer than the screen itself.
        history.clear()
        current = ""
        if (::binding.isInitialized) binding.tvOutput.text = ""
    }
}

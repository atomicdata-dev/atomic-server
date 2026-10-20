package place.atomic.app.kotlin.ui

import kotlin.math.exp
import kotlin.math.ln
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt

/** Width from which the shell shows the sidebar next to the pages (Flutter's `ShellLayout.splitWidth`). */
const val SPLIT_FROM_DP = 600

/** True from [SPLIT_FROM_DP] wide: the tablet layout. */
fun isWide(widthDp: Int) = widthDp >= SPLIT_FROM_DP

/** Room for the bar's six 48 dp slots and its padding. */
const val MIN_LIST_DP = 304f
const val MAX_DRAGGED_DP = 520f
const val MIN_DETAIL_DP = 280f

/** How far past its bounds the sidebar can be pulled, however far the finger goes. */
const val OVERSHOOT_LIMIT_DP = 48f

/**
 * The sidebar's width next to the pages: about two fifths of the room, 320 to
 * 400, or the width it was dragged to; the pages keep at least [MIN_DETAIL_DP].
 */
fun listPaneWidth(room: Float, dragged: Float? = null): Float {
    val max = max(MIN_LIST_DP, min(MAX_DRAGGED_DP, room - MIN_DETAIL_DP))
    return (dragged ?: (room * 0.4f).coerceIn(320f, 400f)).coerceIn(MIN_LIST_DP, max)
}

/** The widest the sidebar is dragged to in [room]. */
fun listPaneMax(room: Float) = max(MIN_LIST_DP, min(MAX_DRAGGED_DP, room - MIN_DETAIL_DP))

/**
 * [width] (plus the 1 dp divider after it) on a whole number of physical pixels:
 * the pages' web view is a texture, and placed at a fraction of a pixel its text
 * turns blurry. A zero or hidden width stays as it is.
 */
fun snapPaneWidth(width: Float, density: Float): Float {
    if (width <= 0.5f || density <= 0f) return width
    return ((width + 1) * density).roundToInt() / density - 1
}

private fun tanh(x: Float): Float {
    val e = exp(2 * x.coerceIn(-20f, 20f))
    return (e - 1) / (e + 1)
}

/**
 * The width shown for a finger at [raw]: the same inside [lo]..[hi], and never
 * more than [OVERSHOOT_LIMIT_DP] past the bound outside it (a tanh band, 1:1 at
 * the bound). The sidebar uses 0 for [lo]: closing is never resisted.
 */
fun rubberBand(raw: Float, lo: Float, hi: Float): Float {
    val l = OVERSHOOT_LIMIT_DP
    return when {
        raw > hi -> hi + l * tanh((raw - hi) / l)
        raw < lo -> lo - l * tanh((lo - raw) / l)
        else -> raw
    }
}

/** The finger position that shows [shown] (the inverse of [rubberBand]). */
fun rubberBandInverse(shown: Float, lo: Float, hi: Float): Float {
    val l = OVERSHOOT_LIMIT_DP
    fun atanh(y: Float): Float {
        val c = y.coerceIn(-0.999999f, 0.999999f)
        return 0.5f * ln((1 + c) / (1 - c))
    }
    return when {
        shown > hi -> hi + l * atanh((shown - hi) / l)
        shown < lo -> lo - l * atanh((lo - shown) / l)
        else -> shown
    }
}

/** How fast the shown width follows the finger at [raw] (1 inside the range). */
fun rubberBandSlope(raw: Float, lo: Float, hi: Float): Float {
    if (raw <= hi && raw >= lo) return 1f
    val t = tanh((if (raw > hi) raw - hi else lo - raw) / OVERSHOOT_LIMIT_DP)
    return 1 - t * t
}

/** A fling faster than this (dp/s) opens or folds the sidebar whatever the distance. */
const val FLING_DP_PER_S = 300f

/** What letting go of the divider does. */
enum class DragEnd { Fold, Open, Settle, BackToFolded }

/**
 * Where a drag of the divider ends. [wasFolded]: the sidebar was folded and the
 * drag opened it from the edge (open past a third of [full] or on a fling right,
 * else back). Unfolded: a fling left or a drag below 60% of the minimum folds
 * it, otherwise it settles at the dragged width.
 */
fun dragEnd(wasFolded: Boolean, shown: Float, raw: Float, full: Float, velocity: Float): DragEnd =
    if (wasFolded) {
        if (velocity > FLING_DP_PER_S || (velocity > -FLING_DP_PER_S && shown > full / 3)) DragEnd.Open else DragEnd.BackToFolded
    } else if (velocity < -FLING_DP_PER_S && shown < full) DragEnd.Fold
    else if (raw < MIN_LIST_DP * 0.6f) DragEnd.Fold
    else DragEnd.Settle

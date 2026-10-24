package place.atomic.app.kotlin.data

import place.atomic.app.kotlin.session.KeyValue

/**
 * Which Home sections show, in which order, and which are folded to their
 * heading. Immutable; every change returns a new layout. The twin of Flutter's
 * `HomeLayout` (`home_sections.dart`): the default is every section in the
 * order of [Section.entries].
 */
data class HomeLayout(
    /** Every section in the order shown; hidden ones keep their place. */
    val order: List<Section> = Section.entries,
    val hidden: Set<Section> = emptySet(),
    val collapsed: Set<Section> = emptySet(),
) {
    /** The sections that show, in order. */
    val visible: List<Section> get() = order.filter { it !in hidden }

    fun toggleCollapsed(s: Section) = copy(collapsed = if (s in collapsed) collapsed - s else collapsed + s)

    fun setHidden(s: Section, hide: Boolean) = copy(hidden = if (hide) hidden + s else hidden - s)

    /** The row at [from] moved to index [to] (the index it ends at). */
    fun reorder(from: Int, to: Int): HomeLayout {
        if (from !in order.indices || to !in order.indices || from == to) return this
        val list = order.toMutableList()
        list.add(to, list.removeAt(from))
        return copy(order = list)
    }

    /** Default order, every section on; folds are kept. */
    fun reset() = HomeLayout(collapsed = collapsed)

    companion object {
        const val ORDER_KEY = "home_sections_order"
        const val HIDDEN_KEY = "home_sections_hidden"
        const val COLLAPSED_KEY = "home_sections_collapsed"

        /**
         * Built from stored names: unknown names are dropped (the Recents section
         * of an older build is one), and a section the store does not know yet goes
         * in at its default place, right after the last stored section that
         * precedes it by default.
         */
        fun fromNames(order: List<String>?, hidden: List<String>?, collapsed: List<String>?): HomeLayout {
            fun sections(names: List<String>?) = names.orEmpty().mapNotNull { Section.byName(it) }.toSet()
            val result = mutableListOf<Section>()
            for (n in order.orEmpty()) Section.byName(n)?.let { if (it !in result) result += it }
            for (s in Section.entries) {
                if (s in result) continue
                val before = result.indexOfLast { it.ordinal < s.ordinal }
                result.add(before + 1, s)
            }
            return HomeLayout(result, sections(hidden), sections(collapsed))
        }

        private fun KeyValue.names(key: String) = getString(key)?.split(',')?.filter { it.isNotEmpty() }

        fun load(kv: KeyValue) = fromNames(kv.names(ORDER_KEY), kv.names(HIDDEN_KEY), kv.names(COLLAPSED_KEY))
    }

    fun save(kv: KeyValue) {
        kv.putString(ORDER_KEY, order.joinToString(",") { it.name })
        kv.putString(HIDDEN_KEY, hidden.joinToString(",") { it.name })
        kv.putString(COLLAPSED_KEY, collapsed.joinToString(",") { it.name })
    }
}

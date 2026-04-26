package com.adblocker.filter.engine

/**
 * Aho-Corasick automaton — O(n) поиск множества паттернов в строке.
 *
 * Заменяет substringRules.any { url.contains(it) } который давал O(n*k).
 * При 50k правилах и URL длиной 200 символов:
 *   До:    50_000 * 200 = 10_000_000 операций на запрос
 *   После: 200 операций на запрос (один проход по URL)
 *
 * Использование:
 *   val ac = AhoCorasick()
 *   ac.addPattern("/ads/")
 *   ac.addPattern("doubleclick")
 *   ac.build()              // строим failure links — вызвать ОДИН раз после всех addPattern
 *   ac.matches("https://doubleclick.net/pixel") // true
 */
class AhoCorasick {

    private val root = Node(id = 0)
    private val nodes = mutableListOf(root)
    var patternCount: Int = 0
        private set
    private var built = false

    // ── Build phase ───────────────────────────────────────────────────────────

    fun addPattern(pattern: String) {
        check(!built) { "Cannot add patterns after build()" }
        if (pattern.isBlank()) return
        var cur = root
        for (ch in pattern) {
            cur = cur.children.getOrPut(ch) {
                Node(id = nodes.size).also { nodes.add(it) }
            }
        }
        if (!cur.isTerminal) {
            cur.isTerminal = true
            patternCount++
        }
    }

    /**
     * Строит failure-функцию (BFS по дереву).
     * ОБЯЗАТЕЛЬНО вызвать перед первым matches().
     */
    fun build() {
        check(!built) { "build() already called" }
        built = true

        val queue = ArrayDeque<Node>()

        // Первый уровень: failure → root
        for (child in root.children.values) {
            child.failure = root
            queue.add(child)
        }

        while (queue.isNotEmpty()) {
            val cur = queue.removeFirst()
            for ((ch, child) in cur.children) {
                // Failure link: идём по failure цепочке родителя
                var failState: Node = cur.failure ?: root
                while (failState != root && ch !in failState.children) {
                    failState = failState.failure ?: root
                }
                child.failure = failState.children[ch]?.takeIf { it != child } ?: root

                // Output link: если по failure нашли terminal — цепляем
                val childFailure = child.failure
                child.output = if (childFailure != null && childFailure.isTerminal)
                    childFailure
                else
                    childFailure?.output

                queue.add(child)
            }
        }
    }

    // ── Search phase ──────────────────────────────────────────────────────────

    /**
     * Возвращает true если text содержит хотя бы один из паттернов.
     * Thread-safe: только читает построенный автомат.
     */
    fun matches(text: String): Boolean {
        if (!built) return false
        var cur = root
        for (ch in text) {
            // Переходы по failure пока нет перехода по ch
            while (cur != root && ch !in cur.children) {
                cur = cur.failure ?: root
            }
            cur = cur.children[ch] ?: root
            if (cur.isTerminal) return true
            if (cur.output != null) return true
        }
        return false
    }

    // ── Node ──────────────────────────────────────────────────────────────────

    private class Node(val id: Int) {
        val children = HashMap<Char, Node>(4)
        var failure: Node? = null
        var output: Node?  = null
        var isTerminal     = false
    }
}

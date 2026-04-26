package com.adblocker.filter.engine

/**
 * filter.engine — DomainTrie
 *
 * Compressed trie for O(k) domain lookups where k = number of labels in the domain.
 *
 * Domains are stored reversed so "ads.example.com" becomes ["com", "example", "ads"].
 * This lets a single trie walk decide both exact and subdomain matches efficiently.
 *
 * Example insertions:
 *   "doubleclick.net"   → matches doubleclick.net and *.doubleclick.net
 *   "ads.google.com"    → matches ads.google.com only
 */
class DomainTrie {

    private val root = TrieNode()

    @Volatile var size: Int = 0
        private set

    /**
     * Insert a domain into the trie.
     * A wildcard flag is set on the node to indicate "block this domain and all subdomains".
     */
    fun insert(domain: String) {
        val labels = domain.lowercase().split('.').reversed()
        var node = root
        for (label in labels) {
            if (label.isEmpty()) continue
            node = node.children.getOrPut(label) { TrieNode() }
        }
        node.isTerminal = true
        size++
    }

    /**
     * Returns true if [domain] is blocked (exact match or subdomain of a blocked domain).
     */
    fun matches(domain: String): Boolean {
        val labels = domain.lowercase().split('.').reversed()
        var node = root
        for (label in labels) {
            if (label.isEmpty()) continue
            // If any ancestor node is terminal, this is a subdomain of a blocked domain.
            if (node.isTerminal) return true
            node = node.children[label] ?: return false
        }
        return node.isTerminal
    }

    private class TrieNode {
        val children = HashMap<String, TrieNode>(4)
        var isTerminal = false
    }
}

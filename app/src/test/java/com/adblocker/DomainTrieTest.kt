package com.adblocker

import com.adblocker.filter.engine.DomainTrie
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for the DomainTrie O(k) lookup engine.
 */
class DomainTrieTest {

    private lateinit var trie: DomainTrie

    @Before
    fun setup() {
        trie = DomainTrie()
    }

    @Test
    fun `exact domain match`() {
        trie.insert("doubleclick.net")
        assertTrue(trie.matches("doubleclick.net"))
    }

    @Test
    fun `subdomain of blocked domain is also blocked`() {
        trie.insert("doubleclick.net")
        assertTrue(trie.matches("cdn.doubleclick.net"))
        assertTrue(trie.matches("sub.cdn.doubleclick.net"))
    }

    @Test
    fun `non-blocked domain passes`() {
        trie.insert("ads.example.com")
        assertFalse(trie.matches("example.com"))
        assertFalse(trie.matches("safe.example.com"))
    }

    @Test
    fun `sibling domain not matched`() {
        trie.insert("ads.example.com")
        assertFalse(trie.matches("news.example.com"))
    }

    @Test
    fun `empty trie matches nothing`() {
        assertFalse(trie.matches("anything.com"))
    }

    @Test
    fun `multiple domains`() {
        trie.insert("tracker.io")
        trie.insert("analytics.com")
        assertTrue(trie.matches("sub.tracker.io"))
        assertTrue(trie.matches("analytics.com"))
        assertFalse(trie.matches("google.com"))
    }

    @Test
    fun `www prefix stripped externally is handled`() {
        trie.insert("example.com")
        // www is a subdomain, so it should match
        assertTrue(trie.matches("www.example.com"))
    }
}

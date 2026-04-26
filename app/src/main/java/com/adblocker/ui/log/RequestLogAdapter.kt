package com.adblocker.ui.log

import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.adblocker.R

/**
 * ui.log — RequestLogAdapter
 *
 * RecyclerView adapter that displays intercepted request entries.
 * Blocked requests are highlighted in red, passed in neutral grey.
 * Uses ListAdapter with DiffUtil for efficient diffing.
 */
class RequestLogAdapter :
    ListAdapter<RequestLogEntry, RequestLogAdapter.LogViewHolder>(DiffCallback) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): LogViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_log_entry, parent, false)
        return LogViewHolder(view)
    }

    override fun onBindViewHolder(holder: LogViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    class LogViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val tvTime: TextView = itemView.findViewById(R.id.tvTime)
        private val tvMethod: TextView = itemView.findViewById(R.id.tvMethod)
        private val tvHost: TextView = itemView.findViewById(R.id.tvHost)
        private val tvPath: TextView = itemView.findViewById(R.id.tvPath)
        private val tvStatus: TextView = itemView.findViewById(R.id.tvStatus)

        fun bind(entry: RequestLogEntry) {
            tvTime.text = entry.displayTime
            tvMethod.text = entry.method
            tvHost.text = entry.host
            tvPath.text = entry.shortUrl

            if (entry.blocked) {
                tvStatus.text = "BLOCKED"
                tvStatus.setTextColor(Color.parseColor("#EF5350"))
                itemView.setBackgroundColor(Color.parseColor("#1AEF5350"))
            } else {
                tvStatus.text = if (entry.responseCode > 0) "${entry.responseCode}" else "PASS"
                tvStatus.setTextColor(Color.parseColor("#66BB6A"))
                itemView.setBackgroundColor(Color.TRANSPARENT)
            }
        }
    }

    private object DiffCallback : DiffUtil.ItemCallback<RequestLogEntry>() {
        override fun areItemsTheSame(a: RequestLogEntry, b: RequestLogEntry) = a.id == b.id
        override fun areContentsTheSame(a: RequestLogEntry, b: RequestLogEntry) = a == b
    }
}

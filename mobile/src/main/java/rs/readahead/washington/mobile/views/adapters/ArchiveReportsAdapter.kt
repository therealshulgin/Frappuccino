package rs.readahead.washington.mobile.views.adapters

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import org.stream.crypto.upload.DiscoveredReport
import rs.readahead.washington.mobile.R

/**
 * RecyclerView adapter for the archive retrieval reports list. The relay is
 * blind (Phase C), so a row has no title and no creation date to show: it
 * carries the identity-free report id, the derivation index it was derived
 * from, and the blob count plus total size. Never "restore" a title or a
 * `createdAt` here — that would mean asking the relay to hold data it must
 * never hold.
 *
 * Do not be misled by the view names: the [ViewHolder] still binds layout
 * views called `title` and `createdAt`, but they are reused slots. `title`
 * receives the report id, `createdAt` receives `#<derivation index>`, and
 * [DiscoveredReport] has no title or timestamp field to put in them.
 *
 * Never dismiss or clear the list once a report has been downloaded. It used
 * to be hidden on the first tap, and the user then could not tell which
 * reports had already been picked. Downloaded rows stay in place and are
 * flagged instead, so a partial batch can be resumed or a report fetched
 * again.
 *
 * No DiffUtil and no item-level animations: the list is fetched once per
 * session and never mutates in place, so a full `notifyDataSetChanged()` is
 * the right refresh.
 *
 * Tap fires [onClick] with the underlying [DiscoveredReport]. Download
 * progress ([markDownloaded], [pendingReports]) is tracked in memory only,
 * for the lifetime of this adapter. Introduced in 4.4.2, the downloaded
 * flagging in 4.4.5.
 */
class ArchiveReportsAdapter(
    private val items: MutableList<DiscoveredReport>,
    private val onClick: (DiscoveredReport) -> Unit,
) : RecyclerView.Adapter<ArchiveReportsAdapter.ViewHolder>() {

    // IDs of reports the user has already downloaded
    // during THIS activity lifetime. Reset on activity recreation
    // (intentional : downloads are permanent in Downloads/Frappuccino
    // but the in-memory "we already did this one" hint is purely a
    // UX nicety and doesn't need to survive process death).
    private val downloaded: MutableSet<String> = mutableSetOf()

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val title: TextView = view.findViewById(R.id.reportTitle)
        val summary: TextView = view.findViewById(R.id.reportSummary)
        val createdAt: TextView = view.findViewById(R.id.reportCreatedAt)
        val check: TextView = view.findViewById(R.id.reportDownloadedCheck)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val v = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_archive_report, parent, false)
        return ViewHolder(v)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val r = items[position]
        // Phase C relay-blind: no title — the identity-free report id IS the row
        // label. The derivation index is a short, human-friendly secondary tag.
        holder.title.text = r.reportId
        holder.summary.text = holder.itemView.context.getString(
            R.string.archive_report_summary,
            r.blobCount,
            humanBytes(r.totalBytes),
        )
        holder.createdAt.text = "#${r.reportIndex}"

        // Visually flag already-downloaded reports.
        val isDownloaded = downloaded.contains(r.reportId)
        holder.check.visibility = if (isDownloaded) View.VISIBLE else View.GONE
        holder.itemView.alpha = if (isDownloaded) 0.55f else 1f

        holder.itemView.setOnClickListener { onClick(r) }
    }

    override fun getItemCount(): Int = items.size

    fun submit(newItems: List<DiscoveredReport>) {
        items.clear()
        items.addAll(newItems)
        notifyDataSetChanged()
    }

    /**
     * Record that [reportId] has been fully downloaded
     * during this activity session and refresh its row to show the
     * checkmark + faded look. Idempotent : re-calling with the same
     * id is a no-op (the set ignores duplicates).
     */
    fun markDownloaded(reportId: String) {
        if (downloaded.add(reportId)) {
            val idx = items.indexOfFirst { it.reportId == reportId }
            if (idx >= 0) notifyItemChanged(idx)
        }
    }

    /**
     * Returns the reports still pending download (i.e.
     * never touched yet by the user this session). Used by the
     * "TOUT TÉLÉCHARGER" flow to skip what this session has already
     * marked, so a re-tap after a partial batch resumes from where it
     * stopped instead of redoing everything. The tracking lives in
     * memory, not on disk: once the activity has been recreated,
     * reports already written to Downloads/Frappuccino can be
     * downloaded again.
     */
    fun pendingReports(): List<DiscoveredReport> =
        items.filter { it.reportId !in downloaded }

    /**
     * (UX bug 2) — used by the activity to detect a tap
     * on an already-downloaded row and surface a confirmation dialog
     * before re-downloading (prevents accidental overwrites on a
     * finger-slip).
     */
    fun isDownloaded(reportId: String): Boolean = reportId in downloaded

    private fun humanBytes(b: Long): String = when {
        b < 1024L -> "$b B"
        b < 1024L * 1024L -> "${b / 1024L} KB"
        b < 1024L * 1024L * 1024L -> "${b / (1024L * 1024L)} MB"
        else -> "%.1f GB".format(b.toDouble() / (1024.0 * 1024.0 * 1024.0))
    }
}

package rs.readahead.washington.mobile.views.adapters

import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.archive.RescueSession

/**
 * Rows of the "not verifiable" section: for each verified report that also
 * holds legacy objects stored without a signature, how many were kept apart,
 * and the buttons to watch or export them.
 *
 * A separate list on purpose, below the reports: these objects are not part of
 * the testimony, so nothing about them appears on a report's own row (except
 * a count), and the buttons here never act on its verified objects.
 *
 * No DiffUtil, as in [ArchiveReportsAdapter].
 */
class ArchiveUnverifiableAdapter(
    private val onPlay: (Int) -> Unit,
    private val onExport: (Int) -> Unit,
) : RecyclerView.Adapter<ArchiveUnverifiableAdapter.ViewHolder>() {

    private var items: List<RescueSession.EntryView> = emptyList()

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val title: TextView = view.findViewById(R.id.unverifiableTitle)
        val export: TextView = view.findViewById(R.id.unverifiableExportState)
        val playBtn: TextView = view.findViewById(R.id.unverifiablePlayBtn)
        val exportBtn: TextView = view.findViewById(R.id.unverifiableExportBtn)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_archive_unverifiable, parent, false)
        return ViewHolder(v)
    }

    override fun getItemCount(): Int = items.size

    /** [entries] as the screen has them; only those with objects kept apart
     *  are shown. */
    @Suppress("NotifyDataSetChanged") // see the class comment
    fun submit(entries: List<RescueSession.EntryView>) {
        items = rows(entries)
        notifyDataSetChanged()
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val e = items[position]
        val ctx = holder.itemView.context
        holder.title.text = ctx.resources.getQuantityString(
            R.plurals.archive_unverifiable_line, e.unverifiableObjects, e.ordinal, e.unverifiableObjects,
        )
        val exportText = exportText(ctx, e)
        holder.export.text = exportText
        holder.export.visibility = if (exportText == null) View.GONE else View.VISIBLE
        holder.export.setTextColor(
            ContextCompat.getColor(
                ctx,
                if (ArchiveReportsAdapter.hasExclusions(e.unverifiableExportOutcome)) R.color.wa_orange else R.color.wa_white,
            ),
        )
        holder.playBtn.visibility = if (e.unverifiableChunks > 0) View.VISIBLE else View.GONE
        holder.exportBtn.visibility =
            if (e.unverifiableExportable > 0 && e.unverifiableExportState != RescueSession.ExportState.RUNNING) {
                View.VISIBLE
            } else {
                View.GONE
            }
        holder.playBtn.setOnClickListener { onPlay(e.ordinal) }
        holder.exportBtn.setOnClickListener { onExport(e.ordinal) }
    }

    private fun exportText(ctx: Context, e: RescueSession.EntryView): String? = when (e.unverifiableExportState) {
        RescueSession.ExportState.NONE -> null
        RescueSession.ExportState.RUNNING ->
            ctx.getString(R.string.archive_export_running, e.unverifiableExportDone, e.unverifiableExportTotal)
        RescueSession.ExportState.DONE -> ArchiveReportsAdapter.exportDoneText(
            ctx, e.unverifiableExportOutcome, R.string.archive_unverifiable_export_done,
        )
        RescueSession.ExportState.FAILED -> ctx.getString(R.string.archive_export_failed)
    }

    companion object {
        /** The reports that have a row in the section. */
        fun rows(entries: List<RescueSession.EntryView>): List<RescueSession.EntryView> =
            entries.filter { it.state == RescueSession.EntryState.VERIFIED && it.unverifiableObjects > 0 }
    }
}

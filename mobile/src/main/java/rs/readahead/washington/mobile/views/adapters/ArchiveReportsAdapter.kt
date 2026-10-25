package rs.readahead.washington.mobile.views.adapters

import android.content.Context
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import rs.readahead.washington.mobile.R
import rs.readahead.washington.mobile.archive.Cut
import rs.readahead.washington.mobile.archive.ExportOutcome
import rs.readahead.washington.mobile.archive.FailureReason
import rs.readahead.washington.mobile.archive.RescueNames
import rs.readahead.washington.mobile.archive.RescueSession
import uniffi.frappuccino.ClosureState
import uniffi.frappuccino.OtsStatus
import uniffi.frappuccino.ReportScheme
import uniffi.frappuccino.ReportStatus
import uniffi.frappuccino.ReportVerdict

/**
 * Rows of the rescue list: one per report the enumeration found, with what
 * its verification concluded.
 *
 * A row shows the report's position in the list and its derivation index,
 * never its `report_id`: the id is the report's address on the relay and has
 * nothing to tell the witness. The relay is blind, so there is no title and no
 * creation date to show either; the date range comes from the relay's own
 * storage clock and the screen says so.
 *
 * Every status and counter comes from the Rust verdict, unchanged: this class
 * chooses wording and colour, never the verdict. A legacy object stored
 * without a signature is not counted among the verified ones here; the
 * screen lists those in a separate section.
 *
 * No DiffUtil: a whole list rebinds on each change of [RescueSession], which
 * happens a few times per second at most.
 */
class ArchiveReportsAdapter(
    private val onVerify: (Int) -> Unit,
    private val onPlay: (Int) -> Unit,
    private val onExport: (Int) -> Unit,
) : RecyclerView.Adapter<ArchiveReportsAdapter.ViewHolder>() {

    private var items: List<RescueSession.EntryView> = emptyList()

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val title: TextView = view.findViewById(R.id.reportTitle)
        val subtitle: TextView = view.findViewById(R.id.reportSubtitle)
        val status: TextView = view.findViewById(R.id.reportStatus)
        val counters: TextView = view.findViewById(R.id.reportCounters)
        val dates: TextView = view.findViewById(R.id.reportDates)
        val ots: TextView = view.findViewById(R.id.reportOts)
        val anomaly: TextView = view.findViewById(R.id.reportAnomaly)
        val export: TextView = view.findViewById(R.id.reportExportState)
        val verifyBtn: TextView = view.findViewById(R.id.reportVerifyBtn)
        val playBtn: TextView = view.findViewById(R.id.reportPlayBtn)
        val exportBtn: TextView = view.findViewById(R.id.reportExportBtn)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_archive_report, parent, false)
        return ViewHolder(v)
    }

    override fun getItemCount(): Int = items.size

    @Suppress("NotifyDataSetChanged") // see the class comment
    fun submit(newItems: List<RescueSession.EntryView>) {
        items = newItems
        notifyDataSetChanged()
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val e = items[position]
        val ctx = holder.itemView.context
        val index = (e.index ?: 0L).toInt()
        holder.title.text = ctx.getString(R.string.archive_report_title, e.ordinal)
        holder.subtitle.text = ctx.getString(
            if (e.scheme == ReportScheme.CHAIN) R.string.archive_report_subtitle_chain
            else R.string.archive_report_subtitle_legacy,
            index,
        )

        val verdict = e.verdict.takeIf { e.state == RescueSession.EntryState.VERIFIED }
        holder.status.text = statusText(ctx, e, verdict)
        holder.status.setTextColor(
            ContextCompat.getColor(ctx, if (isWarning(e, verdict)) R.color.wa_orange else R.color.wa_white),
        )

        show(holder.counters, verdict?.let { countersText(ctx, it) })
        show(holder.dates, datesText(ctx, verdict))
        show(holder.ots, if (verdict != null) e.ots?.let { otsText(ctx, it) } else null)
        show(
            holder.anomaly,
            if (verdict?.closureAnomaly == true) ctx.getString(R.string.archive_anomaly_closure_invalid) else null,
        )
        show(holder.export, exportText(ctx, e))
        holder.export.setTextColor(
            ContextCompat.getColor(ctx, if (hasExclusions(e.exportOutcome)) R.color.wa_orange else R.color.wa_white),
        )

        val idle = e.state != RescueSession.EntryState.VERIFYING
        holder.verifyBtn.visibility =
            if (idle && e.state != RescueSession.EntryState.VERIFIED) View.VISIBLE else View.GONE
        holder.playBtn.visibility = if (verdict != null && e.playableChunks > 0) View.VISIBLE else View.GONE
        holder.exportBtn.visibility =
            if (verdict != null && verdict.verified > 0u && e.exportState != RescueSession.ExportState.RUNNING) {
                View.VISIBLE
            } else {
                View.GONE
            }
        holder.verifyBtn.setOnClickListener { onVerify(e.ordinal) }
        holder.playBtn.setOnClickListener { onPlay(e.ordinal) }
        holder.exportBtn.setOnClickListener { onExport(e.ordinal) }
    }

    private fun show(view: TextView, text: CharSequence?) {
        if (text.isNullOrEmpty()) {
            view.visibility = View.GONE
        } else {
            view.text = text
            view.visibility = View.VISIBLE
        }
    }

    private fun statusText(ctx: Context, e: RescueSession.EntryView, verdict: ReportVerdict?): String =
        when (e.state) {
            RescueSession.EntryState.LISTED ->
                ctx.resources.getQuantityString(R.plurals.archive_report_listed, e.objectCount, e.objectCount)
            RescueSession.EntryState.VERIFYING ->
                ctx.getString(R.string.archive_status_verifying, e.fetched, e.objectCount)
            RescueSession.EntryState.FAILED ->
                ctx.getString(R.string.archive_status_failed, reasonText(ctx, e.failure))
            RescueSession.EntryState.VERIFIED -> when (verdict?.status) {
                ReportStatus.COMPLETE -> ctx.getString(R.string.archive_status_complete)
                ReportStatus.INCOMPLETE -> ctx.getString(R.string.archive_status_incomplete)
                ReportStatus.ALTERED -> ctx.getString(R.string.archive_status_altered)
                ReportStatus.INTERRUPTED -> ctx.getString(R.string.archive_status_interrupted)
                ReportStatus.LEGACY, ReportStatus.DIRECTORY, null ->
                    if (verdict?.closure == ClosureState.VALID) {
                        ctx.getString(R.string.archive_status_legacy_frozen)
                    } else {
                        ctx.getString(R.string.archive_status_legacy)
                    }
            }
        }

    private fun isWarning(e: RescueSession.EntryView, verdict: ReportVerdict?): Boolean = when {
        e.state == RescueSession.EntryState.FAILED -> true
        verdict == null -> false
        else -> verdict.status == ReportStatus.ALTERED ||
            verdict.status == ReportStatus.INCOMPLETE ||
            verdict.status == ReportStatus.INTERRUPTED ||
            verdict.closureAnomaly
    }

    private fun countersText(ctx: Context, v: ReportVerdict): String {
        val r = ctx.resources
        val parts = ArrayList<String>()
        fun add(id: Int, count: UInt, always: Boolean = false) {
            val n = count.toInt()
            if (n > 0 || always) parts.add(r.getQuantityString(id, n, n))
        }
        add(R.plurals.archive_count_verified, v.verified, always = true)
        add(R.plurals.archive_count_missing, v.missing)
        add(R.plurals.archive_count_foreign, v.foreign)
        add(R.plurals.archive_count_unexpected, v.unexpected)
        add(R.plurals.archive_count_unexpected_signed, v.unexpectedSigned)
        add(R.plurals.archive_count_invalid, v.invalid)
        add(R.plurals.archive_count_unverifiable, v.unverifiable)
        add(R.plurals.archive_count_unchecked, v.unchecked)
        return parts.joinToString(" · ")
    }

    private fun datesText(ctx: Context, v: ReportVerdict?): String? {
        val first = v?.firstModified ?: return null
        val last = v.lastModified ?: return null
        return ctx.getString(R.string.archive_dates_range, RescueNames.displayDate(first), RescueNames.displayDate(last))
    }

    private fun otsText(ctx: Context, ots: OtsStatus?): String = when (ots) {
        OtsStatus.MATCH -> ctx.getString(R.string.archive_ots_match)
        OtsStatus.MISMATCH -> ctx.getString(R.string.archive_ots_mismatch)
        OtsStatus.ABSENT, null -> ctx.getString(R.string.archive_ots_absent)
    }

    private fun exportText(ctx: Context, e: RescueSession.EntryView): String? = when (e.exportState) {
        RescueSession.ExportState.NONE -> null
        RescueSession.ExportState.RUNNING -> ctx.getString(R.string.archive_export_running, e.exportDone, e.exportTotal)
        RescueSession.ExportState.DONE -> exportDoneText(ctx, e.exportOutcome, R.string.archive_export_done)
        RescueSession.ExportState.FAILED -> ctx.getString(R.string.archive_export_failed)
    }

    companion object {
        /** Whether the export left out objects that did not decrypt: an
         *  anomaly, shown in the warning colour. */
        fun hasExclusions(outcome: ExportOutcome?): Boolean = (outcome?.undecryptable ?: 0) > 0

        /**
         * The line of a finished export: [done]; for a joined export, how
         * many videos were written and, when there are several, why the
         * recording was cut; then how many objects did not decrypt and were
         * excluded, and whether the timestamp proof went with them.
         */
        fun exportDoneText(ctx: Context, outcome: ExportOutcome?, done: Int): String {
            if (outcome == null) return ctx.getString(done)
            val r = ctx.resources
            val excluded = outcome.undecryptable
            if (outcome.nothingWritten) {
                return r.getQuantityString(R.plurals.archive_export_nothing_decrypted, excluded, excluded)
            }
            val parts = arrayListOf(ctx.getString(done))
            fun add(id: Int, count: Int) {
                if (count > 0) parts.add(r.getQuantityString(id, count, count))
            }
            add(R.plurals.archive_export_videos, outcome.videos)
            if (outcome.videos > 1) {
                for (cut in Cut.entries) add(cutText(cut), outcome.cuts[cut] ?: 0)
            }
            add(R.plurals.archive_export_undecryptable, excluded)
            if (outcome.timestampLeftOut) parts.add(ctx.getString(R.string.archive_export_timestamp_left_out))
            return parts.joinToString(" ")
        }

        /** The wording of a [Cut], with its count. */
        private fun cutText(cut: Cut): Int = when (cut) {
            Cut.MISSING -> R.plurals.archive_export_cut_missing
            Cut.EXCLUDED -> R.plurals.archive_export_cut_excluded
            Cut.NUMBERING -> R.plurals.archive_export_cut_numbering
            Cut.FORMAT -> R.plurals.archive_export_cut_format
            Cut.CODEC -> R.plurals.archive_export_cut_codec
            Cut.SIZE -> R.plurals.archive_export_cut_size
            Cut.OTHER -> R.plurals.archive_export_cut_other
        }

        /** The wording of a [FailureReason]. */
        fun reasonText(ctx: Context, reason: FailureReason?): String = ctx.getString(
            when (reason) {
                FailureReason.RATE_LIMITED -> R.string.archive_reason_rate_limited
                FailureReason.NETWORK -> R.string.archive_reason_network
                FailureReason.STORAGE -> R.string.archive_reason_storage
                FailureReason.REFUSED -> R.string.archive_reason_refused
                FailureReason.PROBE_CAP -> R.string.archive_reason_probe_cap
                FailureReason.OTHER, null -> R.string.archive_reason_other
            },
        )
    }
}

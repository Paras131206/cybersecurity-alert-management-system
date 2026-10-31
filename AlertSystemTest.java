import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/*
 * Test cases for AlertSystem.java.
 * Run this file: it prints PASS or FAIL for each test and a total at the end.
 */
public class AlertSystemTest {

    static int passed = 0, failed = 0;

    static void check(boolean condition, String testName) {
        if (condition) { passed++; System.out.println("PASS  " + testName); }
        else           { failed++; System.out.println("FAIL  " + testName); }
    }

    // returns true if the code throws the expected kind of exception
    static boolean throwsError(Runnable code, Class<?> expected) {
        try { code.run(); } catch (Exception e) { return expected.isInstance(e); }
        return false;
    }

    // takes alerts out of the priority queue one by one and returns their ids
    static List<Integer> takeAll(AlertSystem.AlertManager m) {
        List<Integer> ids = new ArrayList<>();
        AlertSystem.Alert a;
        while ((a = m.assignNext()) != null) ids.add(a.id);
        return ids;
    }

    static List<Integer> ids(List<AlertSystem.Alert> alerts) {
        List<Integer> ids = new ArrayList<>();
        for (AlertSystem.Alert a : alerts) ids.add(a.id);
        return ids;
    }

    static void runTests() throws Exception {
        // 1
        AlertSystem.AlertManager m = new AlertSystem.AlertManager();
        AlertSystem.Alert a1 = m.submit("10.0.0.1", "Port scan", AlertSystem.Severity.LOW, "x");
        AlertSystem.Alert a2 = m.submit("10.0.0.2", "Malware", AlertSystem.Severity.HIGH, "y");
        check(a1.id == 1 && a2.id == 2 && a1.status == AlertSystem.Status.QUEUED
                && m.pendingCount() == 2 && m.triagedCount() == 0 && m.totalCount() == 2,
                "1. submit gives increasing ids and status QUEUED");

        // 2
        AlertSystem.Alert t = new AlertSystem.AlertManager().submit("  host-7  ", "  DDoS ", AlertSystem.Severity.MEDIUM, null);
        check(t.source.equals("host-7") && t.type.equals("DDoS") && t.description.equals(""),
                "2. submit trims text and turns null description into empty");

        // 3
        AlertSystem.AlertManager m3 = new AlertSystem.AlertManager();
        check(throwsError(() -> m3.submit(null, "t", AlertSystem.Severity.LOW, ""), IllegalArgumentException.class)
                && throwsError(() -> m3.submit("   ", "t", AlertSystem.Severity.LOW, ""), IllegalArgumentException.class)
                && throwsError(() -> m3.submit("s", "", AlertSystem.Severity.LOW, ""), IllegalArgumentException.class)
                && throwsError(() -> m3.submit("s", "t", null, ""), IllegalArgumentException.class)
                && m3.totalCount() == 0,
                "3. submit rejects empty source/type and null severity");

        // 4
        LocalDateTime before = LocalDateTime.now();
        AlertSystem.Alert timed = new AlertSystem.AlertManager().submit("s", "t", AlertSystem.Severity.LOW, "");
        check(timed.createdAt != null && !timed.createdAt.isBefore(before)
                && !timed.createdAt.isAfter(LocalDateTime.now()),
                "4. every alert gets the time it was created");

        // 5
        AlertSystem.AlertManager m5 = new AlertSystem.AlertManager();
        m5.submit("s", "t", AlertSystem.Severity.CRITICAL, "");
        check(m5.assignNext() == null && m5.peekNext() == null,
                "5. alerts cannot be assigned before triage");

        // 6
        AlertSystem.AlertManager m6 = new AlertSystem.AlertManager();
        m6.submit("s", "t", AlertSystem.Severity.LOW, "");
        m6.submit("s", "t", AlertSystem.Severity.LOW, "");
        check(m6.triagePending() == 2 && m6.triagePending() == 0
                && m6.pendingCount() == 0 && m6.triagedCount() == 2 && m6.find(1).status == AlertSystem.Status.TRIAGED,
                "6. triagePending moves everything and is safe to repeat");

        // 7
        AlertSystem.AlertManager m7 = new AlertSystem.AlertManager();
        m7.submit("s", "a", AlertSystem.Severity.LOW, "");        // 1
        m7.submit("s", "b", AlertSystem.Severity.CRITICAL, "");   // 2
        m7.submit("s", "c", AlertSystem.Severity.HIGH, "");       // 3
        m7.submit("s", "d", AlertSystem.Severity.CRITICAL, "");   // 4
        m7.submit("s", "e", AlertSystem.Severity.MEDIUM, "");     // 5
        m7.triagePending();
        boolean peekOk = m7.peekNext().id == 2 && m7.triagedCount() == 5;
        check(peekOk && takeAll(m7).equals(List.of(2, 4, 3, 5, 1)),
                "7. most severe first, older first when severity is equal");

        // 8
        AlertSystem.AlertManager m8 = new AlertSystem.AlertManager();
        check(m8.assignNext() == null && m8.peekNext() == null,
                "8. empty system returns null, never crashes");

        // 9
        AlertSystem.AlertManager m9 = new AlertSystem.AlertManager();
        m9.submit("s", "t", AlertSystem.Severity.HIGH, "");
        m9.triagePending();
        check(m9.assignNext().status == AlertSystem.Status.ASSIGNED, "9. assigned alert gets status ASSIGNED");

        // 10
        AlertSystem.AlertManager m10 = new AlertSystem.AlertManager();
        m10.submit("s", "t", AlertSystem.Severity.HIGH, "");
        m10.triagePending();
        m10.assignNext();
        AlertSystem.Alert r = m10.resolve(1, "  Blocked IP  ");
        check(r.status == AlertSystem.Status.RESOLVED && r.note.equals("Blocked IP"),
                "10. resolve closes an assigned alert with a note");

        // 11
        AlertSystem.AlertManager m11 = new AlertSystem.AlertManager();
        m11.submit("s", "t", AlertSystem.Severity.HIGH, "");
        boolean ok = throwsError(() -> m11.resolve(1, "n"), IllegalStateException.class);   // QUEUED
        m11.triagePending();
        ok = ok && throwsError(() -> m11.resolve(1, "n"), IllegalStateException.class);     // TRIAGED
        m11.assignNext();
        ok = ok && throwsError(() -> m11.resolve(1, " "), IllegalArgumentException.class)   // blank note
                && m11.find(1).status == AlertSystem.Status.ASSIGNED;
        m11.resolve(1, "done");
        ok = ok && throwsError(() -> m11.resolve(1, "again"), IllegalStateException.class)  // already resolved
                && throwsError(() -> m11.resolve(99, "n"), IllegalArgumentException.class); // unknown id
        check(ok, "11. resolve rejects wrong status, blank note and unknown id");

        // 12
        AlertSystem.AlertManager m12 = new AlertSystem.AlertManager();
        m12.submit("s", "t", AlertSystem.Severity.HIGH, "");     // 1
        m12.submit("s", "t", AlertSystem.Severity.LOW, "");      // 2
        m12.submit("s", "t", AlertSystem.Severity.MEDIUM, "");   // 3
        m12.triagePending();
        m12.escalate(2, AlertSystem.Severity.CRITICAL);
        check(m12.triagedCount() == 3 && takeAll(m12).equals(List.of(2, 1, 3)),
                "12. escalating a triaged alert moves it up the priority queue");

        // 13
        AlertSystem.AlertManager m13 = new AlertSystem.AlertManager();
        m13.submit("s", "t", AlertSystem.Severity.HIGH, "");     // 1
        m13.submit("s", "t", AlertSystem.Severity.LOW, "");      // 2
        m13.escalate(2, AlertSystem.Severity.CRITICAL);
        m13.triagePending();
        check(m13.assignNext().id == 2, "13. escalating a queued alert counts at triage");

        // 14
        AlertSystem.AlertManager m14 = new AlertSystem.AlertManager();
        m14.submit("s", "t", AlertSystem.Severity.HIGH, "");
        ok = throwsError(() -> m14.escalate(1, AlertSystem.Severity.HIGH), IllegalArgumentException.class)
                && throwsError(() -> m14.escalate(1, AlertSystem.Severity.LOW), IllegalArgumentException.class)
                && throwsError(() -> m14.escalate(1, null), IllegalArgumentException.class)
                && throwsError(() -> m14.escalate(7, AlertSystem.Severity.CRITICAL), IllegalArgumentException.class);
        m14.triagePending();
        m14.assignNext();
        ok = ok && throwsError(() -> m14.escalate(1, AlertSystem.Severity.CRITICAL), IllegalStateException.class)
                && m14.find(1).severity == AlertSystem.Severity.HIGH;
        check(ok, "14. escalate rejects same/lower/null severity, unknown id and assigned alerts");

        // 15
        AlertSystem.AlertManager m15 = new AlertSystem.AlertManager();
        m15.submit("a", "t", AlertSystem.Severity.LOW, "");
        m15.submit("b", "t", AlertSystem.Severity.LOW, "");
        check(m15.find(2).source.equals("b") && m15.find(0) == null && m15.find(3) == null && m15.find(-5) == null,
                "15. find returns the alert, or null for unknown ids");

        // 16
        AlertSystem.AlertManager m16 = new AlertSystem.AlertManager();
        for (int i = 0; i < 10; i++) m16.submit("s", "t", AlertSystem.Severity.LOW, "");
        check(ids(m16.findInRange(3, 6)).equals(List.of(3, 4, 5, 6))
                && ids(m16.findInRange(5, 5)).equals(List.of(5))
                && m16.findInRange(20, 30).isEmpty()
                && m16.findInRange(-100, 2).size() == 2
                && throwsError(() -> m16.findInRange(6, 3), IllegalArgumentException.class),
                "16. findInRange is inclusive, sorted and handles edges");

        // 17
        AlertSystem.AlertManager m17 = new AlertSystem.AlertManager();
        for (int i = 0; i < 5; i++) m17.submit("s", "t", AlertSystem.Severity.values()[i % 4], "");
        m17.triagePending();
        m17.resolve(m17.assignNext().id, "done");
        check(ids(m17.getAllAlerts()).equals(List.of(1, 2, 3, 4, 5)) && new AlertSystem.AlertManager().getAllAlerts().isEmpty(),
                "17. getAllAlerts keeps every alert in id order, even resolved ones");

        // 18
        AlertSystem.AlertBST big = new AlertSystem.AlertBST();
        for (int i = 1; i <= 200_000; i++) big.insert(new AlertSystem.Alert(i, "s", "t", AlertSystem.Severity.LOW, ""));
        check(big.size == 200_000 && big.height(big.root) <= 26
                && big.search(123_456).id == 123_456 && big.range(1, 200_000).size() == 200_000,
                "18. BST stays balanced with 200,000 alerts");

        // 19
        AlertSystem.AlertBST tree = new AlertSystem.AlertBST();
        tree.insert(new AlertSystem.Alert(1, "s", "t", AlertSystem.Severity.LOW, ""));
        check(throwsError(() -> tree.insert(new AlertSystem.Alert(1, "s", "t", AlertSystem.Severity.LOW, "")), IllegalArgumentException.class)
                && throwsError(() -> tree.insert(null), IllegalArgumentException.class)
                && tree.size == 1,
                "19. BST rejects duplicate ids and null");

        // 20
        String text = new AlertSystem.Alert(9, "10.0.0.9", "Port scan", AlertSystem.Severity.LOW, "").toString();
        check(text.contains("#9") && text.contains("LOW") && text.contains("Port scan"),
                "20. alert prints in a readable way");

        // 21
        AlertSystem.AlertManager m21 = new AlertSystem.AlertManager();
        for (int i = 0; i < 50_000; i++) m21.submit("s", "t", AlertSystem.Severity.values()[i % 4], "");
        m21.triagePending();
        AlertSystem.Severity last = AlertSystem.Severity.CRITICAL;
        boolean order = true;
        int done = 0;
        AlertSystem.Alert next;
        while ((next = m21.assignNext()) != null) {
            if (next.severity.compareTo(last) > 0) order = false;
            last = next.severity;
            m21.resolve(next.id, "ok");
            done++;
        }
        check(order && done == 50_000, "21. 50,000 alerts all handled in the right order");

        // 22
        AlertSystem.AlertManager m22 = new AlertSystem.AlertManager();
        List<Thread> threads = new ArrayList<>();
        for (int t2 = 0; t2 < 8; t2++) {
            Thread th = new Thread(() -> {
                for (int i = 0; i < 2000; i++) m22.submit("s", "t", AlertSystem.Severity.MEDIUM, "");
            });
            threads.add(th);
            th.start();
        }
        for (Thread th : threads) th.join();
        check(m22.totalCount() == 16_000 && m22.triagePending() == 16_000,
                "22. 8 threads adding alerts at once lose nothing");

        System.out.println("\n" + passed + " passed, " + failed + " failed");
    }

    public static void main(String[] args) throws Exception {
        runTests();
        if (failed > 0) System.exit(1);
    }
}

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.PriorityQueue;
import java.util.Queue;

/*
 * Cybersecurity Alert Management System
 *
 * Data structures used:
 *   1. Queue          -> new alerts wait here in arrival order (first come, first served)
 *   2. Priority Queue -> triaged alerts; the most severe alert comes out first
 *   3. Binary Search Tree (BST) -> stores every alert by id for fast searching
 *
 * Alert life: QUEUED -> TRIAGED -> ASSIGNED -> RESOLVED
 *
 * Run this file: it shows a demo and then runs all the test cases.
 */
public class AlertSystem {

    // ---------------- Severity and Status ----------------

    enum Severity { LOW, MEDIUM, HIGH, CRITICAL }          // lowest to highest

    enum Status { QUEUED, TRIAGED, ASSIGNED, RESOLVED }

    // ---------------- Alert ----------------

    static class Alert {
        int id;
        String source;
        String type;
        String description;
        Severity severity;
        Status status;
        String note;                  // written when the alert is resolved
        LocalDateTime createdAt;

        Alert(int id, String source, String type, Severity severity, String description) {
            this.id = id;
            this.source = source;
            this.type = type;
            this.severity = severity;
            this.description = description;
            this.status = Status.QUEUED;
            this.createdAt = LocalDateTime.now();
        }

        public String toString() {
            return "#" + id + " [" + severity + "] " + type + " from " + source + " (" + status + ")";
        }
    }

    // ---------------- Binary Search Tree (AVL, so it stays balanced) ----------------

    static class AlertBST {

        class Node {
            Alert alert;
            Node left, right;
            int height = 1;

            Node(Alert alert) { this.alert = alert; }
        }

        Node root;
        int size = 0;

        void insert(Alert alert) {
            if (alert == null) throw new IllegalArgumentException("alert is null");
            root = insert(root, alert);
            size++;
        }

        private Node insert(Node node, Alert alert) {
            if (node == null) return new Node(alert);

            if (alert.id < node.alert.id)      node.left = insert(node.left, alert);
            else if (alert.id > node.alert.id) node.right = insert(node.right, alert);
            else throw new IllegalArgumentException("Duplicate id " + alert.id);

            return balance(node);
        }

        Alert search(int id) {
            Node current = root;
            while (current != null) {
                if (id == current.alert.id) return current.alert;
                current = (id < current.alert.id) ? current.left : current.right;
            }
            return null;                                       // not found
        }

        // alerts with low <= id <= high, in increasing id order (in-order traversal)
        List<Alert> range(int low, int high) {
            List<Alert> result = new ArrayList<>();
            inorder(root, low, high, result);
            return result;
        }

        private void inorder(Node node, int low, int high, List<Alert> result) {
            if (node == null) return;
            if (low < node.alert.id) inorder(node.left, low, high, result);
            if (low <= node.alert.id && node.alert.id <= high) result.add(node.alert);
            if (high > node.alert.id) inorder(node.right, low, high, result);
        }

        // --- AVL balancing: ids come in increasing order, so without this the tree becomes a list ---

        int height(Node n) { return n == null ? 0 : n.height; }

        private void updateHeight(Node n) { n.height = 1 + Math.max(height(n.left), height(n.right)); }

        private Node rotateRight(Node y) {
            Node x = y.left;
            y.left = x.right;
            x.right = y;
            updateHeight(y);
            updateHeight(x);
            return x;
        }

        private Node rotateLeft(Node x) {
            Node y = x.right;
            x.right = y.left;
            y.left = x;
            updateHeight(x);
            updateHeight(y);
            return y;
        }

        private Node balance(Node node) {
            updateHeight(node);
            int bf = height(node.left) - height(node.right);     // balance factor

            if (bf > 1) {                                        // left heavy
                if (height(node.left.left) < height(node.left.right)) node.left = rotateLeft(node.left);
                return rotateRight(node);
            }
            if (bf < -1) {                                       // right heavy
                if (height(node.right.right) < height(node.right.left)) node.right = rotateRight(node.right);
                return rotateLeft(node);
            }
            return node;
        }
    }

    // ---------------- Alert Manager (uses all three data structures) ----------------

    static class AlertManager {

        Queue<Alert> incoming = new LinkedList<>();                        // 1. Queue
        PriorityQueue<Alert> triage = new PriorityQueue<>((a, b) -> {      // 2. Priority queue
            if (a.severity != b.severity) return b.severity.compareTo(a.severity); // higher severity first
            return a.id - b.id;                                                   // then older first
        });
        AlertBST allAlerts = new AlertBST();                               // 3. BST
        int nextId = 1;

        // a new alert goes into the queue and the BST
        synchronized Alert submit(String source, String type, Severity severity, String description) {
            if (source == null || source.trim().isEmpty()) throw new IllegalArgumentException("source is empty");
            if (type == null || type.trim().isEmpty()) throw new IllegalArgumentException("type is empty");
            if (severity == null) throw new IllegalArgumentException("severity is null");
            if (description == null) description = "";

            Alert alert = new Alert(nextId++, source.trim(), type.trim(), severity, description.trim());
            incoming.add(alert);
            allAlerts.insert(alert);
            return alert;
        }

        // move every waiting alert from the queue into the priority queue
        synchronized int triagePending() {
            int count = 0;
            while (!incoming.isEmpty()) {
                Alert alert = incoming.poll();
                alert.status = Status.TRIAGED;
                triage.add(alert);
                count++;
            }
            return count;
        }

        // see the next alert without removing it (null if none)
        synchronized Alert peekNext() {
            return triage.peek();
        }

        // give the most urgent alert to an analyst (null if none)
        synchronized Alert assignNext() {
            Alert alert = triage.poll();
            if (alert != null) alert.status = Status.ASSIGNED;
            return alert;
        }

        synchronized Alert resolve(int id, String note) {
            Alert alert = find(id);
            if (alert == null) throw new IllegalArgumentException("No alert with id " + id);
            if (alert.status != Status.ASSIGNED) throw new IllegalStateException("Alert must be ASSIGNED first");
            if (note == null || note.trim().isEmpty()) throw new IllegalArgumentException("note is empty");

            alert.note = note.trim();
            alert.status = Status.RESOLVED;
            return alert;
        }

        // raise the severity of an alert that no analyst has picked up yet
        synchronized Alert escalate(int id, Severity newSeverity) {
            Alert alert = find(id);
            if (alert == null) throw new IllegalArgumentException("No alert with id " + id);
            if (newSeverity == null || newSeverity.compareTo(alert.severity) <= 0)
                throw new IllegalArgumentException("New severity must be higher");

            if (alert.status == Status.QUEUED) {
                alert.severity = newSeverity;
            } else if (alert.status == Status.TRIAGED) {
                triage.remove(alert);            // take it out, change it, put it back in the right place
                alert.severity = newSeverity;
                triage.add(alert);
            } else {
                throw new IllegalStateException("Alert is already " + alert.status);
            }
            return alert;
        }

        synchronized Alert find(int id) { return allAlerts.search(id); }

        synchronized List<Alert> findInRange(int low, int high) {
            if (low > high) throw new IllegalArgumentException("low is greater than high");
            return allAlerts.range(low, high);
        }

        synchronized List<Alert> getAllAlerts() { return allAlerts.range(Integer.MIN_VALUE, Integer.MAX_VALUE); }

        synchronized int pendingCount() { return incoming.size(); }

        synchronized int triagedCount() { return triage.size(); }

        synchronized int totalCount() { return allAlerts.size; }
    }

    // ---------------- Demo ----------------

    static void demo() {
        AlertManager soc = new AlertManager();
        soc.submit("10.0.0.15", "Port scan", Severity.LOW, "Ports 1-1024 probed");
        soc.submit("10.0.0.22", "Brute-force login", Severity.HIGH, "200 failed SSH logins");
        soc.submit("10.0.1.5", "Malware", Severity.CRITICAL, "Ransomware on file server");
        soc.submit("192.168.1.40", "Phishing email", Severity.MEDIUM, "Reported by finance");

        System.out.println("New alerts (queue): " + soc.pendingCount());
        soc.triagePending();
        soc.escalate(4, Severity.CRITICAL);                      // phishing turned out to be serious

        System.out.println("Analysts handle alerts, most urgent first:");
        Alert a;
        while ((a = soc.assignNext()) != null) {
            System.out.println("  " + a);
            soc.resolve(a.id, "Handled");
        }
        System.out.println("Search id 3 in BST: " + soc.find(3));
        System.out.println("Search id 9 in BST: " + soc.find(9));
        System.out.println();
    }

    // ---------------- Tests ----------------

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
    static List<Integer> takeAll(AlertManager m) {
        List<Integer> ids = new ArrayList<>();
        Alert a;
        while ((a = m.assignNext()) != null) ids.add(a.id);
        return ids;
    }

    static List<Integer> ids(List<Alert> alerts) {
        List<Integer> ids = new ArrayList<>();
        for (Alert a : alerts) ids.add(a.id);
        return ids;
    }

    static void runTests() throws Exception {
        // 1
        AlertManager m = new AlertManager();
        Alert a1 = m.submit("10.0.0.1", "Port scan", Severity.LOW, "x");
        Alert a2 = m.submit("10.0.0.2", "Malware", Severity.HIGH, "y");
        check(a1.id == 1 && a2.id == 2 && a1.status == Status.QUEUED
                && m.pendingCount() == 2 && m.triagedCount() == 0 && m.totalCount() == 2,
                "1. submit gives increasing ids and status QUEUED");

        // 2
        Alert t = new AlertManager().submit("  host-7  ", "  DDoS ", Severity.MEDIUM, null);
        check(t.source.equals("host-7") && t.type.equals("DDoS") && t.description.equals(""),
                "2. submit trims text and turns null description into empty");

        // 3
        AlertManager m3 = new AlertManager();
        check(throwsError(() -> m3.submit(null, "t", Severity.LOW, ""), IllegalArgumentException.class)
                && throwsError(() -> m3.submit("   ", "t", Severity.LOW, ""), IllegalArgumentException.class)
                && throwsError(() -> m3.submit("s", "", Severity.LOW, ""), IllegalArgumentException.class)
                && throwsError(() -> m3.submit("s", "t", null, ""), IllegalArgumentException.class)
                && m3.totalCount() == 0,
                "3. submit rejects empty source/type and null severity");

        // 4
        LocalDateTime before = LocalDateTime.now();
        Alert timed = new AlertManager().submit("s", "t", Severity.LOW, "");
        check(timed.createdAt != null && !timed.createdAt.isBefore(before)
                && !timed.createdAt.isAfter(LocalDateTime.now()),
                "4. every alert gets the time it was created");

        // 5
        AlertManager m5 = new AlertManager();
        m5.submit("s", "t", Severity.CRITICAL, "");
        check(m5.assignNext() == null && m5.peekNext() == null,
                "5. alerts cannot be assigned before triage");

        // 6
        AlertManager m6 = new AlertManager();
        m6.submit("s", "t", Severity.LOW, "");
        m6.submit("s", "t", Severity.LOW, "");
        check(m6.triagePending() == 2 && m6.triagePending() == 0
                && m6.pendingCount() == 0 && m6.triagedCount() == 2 && m6.find(1).status == Status.TRIAGED,
                "6. triagePending moves everything and is safe to repeat");

        // 7
        AlertManager m7 = new AlertManager();
        m7.submit("s", "a", Severity.LOW, "");        // 1
        m7.submit("s", "b", Severity.CRITICAL, "");   // 2
        m7.submit("s", "c", Severity.HIGH, "");       // 3
        m7.submit("s", "d", Severity.CRITICAL, "");   // 4
        m7.submit("s", "e", Severity.MEDIUM, "");     // 5
        m7.triagePending();
        boolean peekOk = m7.peekNext().id == 2 && m7.triagedCount() == 5;
        check(peekOk && takeAll(m7).equals(List.of(2, 4, 3, 5, 1)),
                "7. most severe first, older first when severity is equal");

        // 8
        AlertManager m8 = new AlertManager();
        check(m8.assignNext() == null && m8.peekNext() == null,
                "8. empty system returns null, never crashes");

        // 9
        AlertManager m9 = new AlertManager();
        m9.submit("s", "t", Severity.HIGH, "");
        m9.triagePending();
        check(m9.assignNext().status == Status.ASSIGNED, "9. assigned alert gets status ASSIGNED");

        // 10
        AlertManager m10 = new AlertManager();
        m10.submit("s", "t", Severity.HIGH, "");
        m10.triagePending();
        m10.assignNext();
        Alert r = m10.resolve(1, "  Blocked IP  ");
        check(r.status == Status.RESOLVED && r.note.equals("Blocked IP"),
                "10. resolve closes an assigned alert with a note");

        // 11
        AlertManager m11 = new AlertManager();
        m11.submit("s", "t", Severity.HIGH, "");
        boolean ok = throwsError(() -> m11.resolve(1, "n"), IllegalStateException.class);   // QUEUED
        m11.triagePending();
        ok = ok && throwsError(() -> m11.resolve(1, "n"), IllegalStateException.class);     // TRIAGED
        m11.assignNext();
        ok = ok && throwsError(() -> m11.resolve(1, " "), IllegalArgumentException.class)   // blank note
                && m11.find(1).status == Status.ASSIGNED;
        m11.resolve(1, "done");
        ok = ok && throwsError(() -> m11.resolve(1, "again"), IllegalStateException.class)  // already resolved
                && throwsError(() -> m11.resolve(99, "n"), IllegalArgumentException.class); // unknown id
        check(ok, "11. resolve rejects wrong status, blank note and unknown id");

        // 12
        AlertManager m12 = new AlertManager();
        m12.submit("s", "t", Severity.HIGH, "");     // 1
        m12.submit("s", "t", Severity.LOW, "");      // 2
        m12.submit("s", "t", Severity.MEDIUM, "");   // 3
        m12.triagePending();
        m12.escalate(2, Severity.CRITICAL);
        check(m12.triagedCount() == 3 && takeAll(m12).equals(List.of(2, 1, 3)),
                "12. escalating a triaged alert moves it up the priority queue");

        // 13
        AlertManager m13 = new AlertManager();
        m13.submit("s", "t", Severity.HIGH, "");     // 1
        m13.submit("s", "t", Severity.LOW, "");      // 2
        m13.escalate(2, Severity.CRITICAL);
        m13.triagePending();
        check(m13.assignNext().id == 2, "13. escalating a queued alert counts at triage");

        // 14
        AlertManager m14 = new AlertManager();
        m14.submit("s", "t", Severity.HIGH, "");
        ok = throwsError(() -> m14.escalate(1, Severity.HIGH), IllegalArgumentException.class)
                && throwsError(() -> m14.escalate(1, Severity.LOW), IllegalArgumentException.class)
                && throwsError(() -> m14.escalate(1, null), IllegalArgumentException.class)
                && throwsError(() -> m14.escalate(7, Severity.CRITICAL), IllegalArgumentException.class);
        m14.triagePending();
        m14.assignNext();
        ok = ok && throwsError(() -> m14.escalate(1, Severity.CRITICAL), IllegalStateException.class)
                && m14.find(1).severity == Severity.HIGH;
        check(ok, "14. escalate rejects same/lower/null severity, unknown id and assigned alerts");

        // 15
        AlertManager m15 = new AlertManager();
        m15.submit("a", "t", Severity.LOW, "");
        m15.submit("b", "t", Severity.LOW, "");
        check(m15.find(2).source.equals("b") && m15.find(0) == null && m15.find(3) == null && m15.find(-5) == null,
                "15. find returns the alert, or null for unknown ids");

        // 16
        AlertManager m16 = new AlertManager();
        for (int i = 0; i < 10; i++) m16.submit("s", "t", Severity.LOW, "");
        check(ids(m16.findInRange(3, 6)).equals(List.of(3, 4, 5, 6))
                && ids(m16.findInRange(5, 5)).equals(List.of(5))
                && m16.findInRange(20, 30).isEmpty()
                && m16.findInRange(-100, 2).size() == 2
                && throwsError(() -> m16.findInRange(6, 3), IllegalArgumentException.class),
                "16. findInRange is inclusive, sorted and handles edges");

        // 17
        AlertManager m17 = new AlertManager();
        for (int i = 0; i < 5; i++) m17.submit("s", "t", Severity.values()[i % 4], "");
        m17.triagePending();
        m17.resolve(m17.assignNext().id, "done");
        check(ids(m17.getAllAlerts()).equals(List.of(1, 2, 3, 4, 5)) && new AlertManager().getAllAlerts().isEmpty(),
                "17. getAllAlerts keeps every alert in id order, even resolved ones");

        // 18
        AlertBST big = new AlertBST();
        for (int i = 1; i <= 200_000; i++) big.insert(new Alert(i, "s", "t", Severity.LOW, ""));
        check(big.size == 200_000 && big.height(big.root) <= 26
                && big.search(123_456).id == 123_456 && big.range(1, 200_000).size() == 200_000,
                "18. BST stays balanced with 200,000 alerts");

        // 19
        AlertBST tree = new AlertBST();
        tree.insert(new Alert(1, "s", "t", Severity.LOW, ""));
        check(throwsError(() -> tree.insert(new Alert(1, "s", "t", Severity.LOW, "")), IllegalArgumentException.class)
                && throwsError(() -> tree.insert(null), IllegalArgumentException.class)
                && tree.size == 1,
                "19. BST rejects duplicate ids and null");

        // 20
        String text = new Alert(9, "10.0.0.9", "Port scan", Severity.LOW, "").toString();
        check(text.contains("#9") && text.contains("LOW") && text.contains("Port scan"),
                "20. alert prints in a readable way");

        // 21
        AlertManager m21 = new AlertManager();
        for (int i = 0; i < 50_000; i++) m21.submit("s", "t", Severity.values()[i % 4], "");
        m21.triagePending();
        Severity last = Severity.CRITICAL;
        boolean order = true;
        int done = 0;
        Alert next;
        while ((next = m21.assignNext()) != null) {
            if (next.severity.compareTo(last) > 0) order = false;
            last = next.severity;
            m21.resolve(next.id, "ok");
            done++;
        }
        check(order && done == 50_000, "21. 50,000 alerts all handled in the right order");

        // 22
        AlertManager m22 = new AlertManager();
        List<Thread> threads = new ArrayList<>();
        for (int t2 = 0; t2 < 8; t2++) {
            Thread th = new Thread(() -> {
                for (int i = 0; i < 2000; i++) m22.submit("s", "t", Severity.MEDIUM, "");
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
        demo();
        runTests();
        if (failed > 0) System.exit(1);
    }
}

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
 * Run this file to see a demo. The test cases are in AlertSystemTest.java.
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
    }

    public static void main(String[] args) {
        demo();
    }
}

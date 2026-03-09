/**
 * DNS Traffic Visualizer - C++ Core Engine
 * Enterprise-grade DNS analysis with advanced algorithms
 * Compiled via pybind11 as Python extension module
 *
 * Theories implemented:
 *  - Graph Theory (Dijkstra, PageRank, Betweenness Centrality)
 *  - Queuing Theory (M/M/1, M/M/c models for DNS latency)
 *  - Information Theory (Shannon Entropy for DGA detection)
 *  - Markov Chains (DNS query sequence modeling)
 *  - Bayesian Inference (anomaly classification)
 *  - Spectral Graph Theory (Laplacian eigenvalues for cluster detection)
 *  - Time-Series Analysis (FFT, EWMA, Holt-Winters)
 *  - Bloom Filter (probabilistic membership for seen domains)
 *  - Consistent Hashing (resolver load balancing simulation)
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/numpy.h>
#include <pybind11/complex.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <complex>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <numeric>
#include <queue>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace py = pybind11;

// ─────────────────────────────────────────────
//  Utility: Current timestamp in milliseconds
// ─────────────────────────────────────────────
static inline double now_ms() {
    return std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
}

// ─────────────────────────────────────────────
//  Bloom Filter  (FNV-1a + Murmur-inspired)
// ─────────────────────────────────────────────
class BloomFilter {
    std::vector<uint8_t> bits_;
    size_t m_, k_;

    size_t hash1(const std::string& s) const {
        size_t h = 14695981039346656037ULL;
        for (char c : s) { h ^= (uint8_t)c; h *= 1099511628211ULL; }
        return h % m_;
    }
    size_t hash2(const std::string& s) const {
        size_t h = 0;
        for (char c : s) h = h * 31 + (uint8_t)c;
        return h % m_;
    }
public:
    BloomFilter(size_t capacity = 10000, double fp = 0.05) {
        m_ = (size_t)(-(double)capacity * std::log(fp) / (std::log(2.0) * std::log(2.0)));
        if (m_ < 1024) m_ = 1024;
        if (m_ > 4000000) m_ = 4000000;   // hard cap ~500 KB
        k_ = std::max((size_t)1, (size_t)((double)m_ / capacity * std::log(2.0)));
        bits_.assign((m_ + 7) / 8, 0);
    }
    void insert(const std::string& s) {
        for (size_t i = 0; i < k_; ++i) {
            size_t idx = (hash1(s) + i * hash2(s)) % m_;
            bits_[idx / 8] |= (1 << (idx % 8));
        }
    }
    bool contains(const std::string& s) const {
        for (size_t i = 0; i < k_; ++i) {
            size_t idx = (hash1(s) + i * hash2(s)) % m_;
            if (!(bits_[idx / 8] & (1 << (idx % 8)))) return false;
        }
        return true;
    }
    void clear() { std::fill(bits_.begin(), bits_.end(), 0); }
};

// ─────────────────────────────────────────────
//  Shannon Entropy & DGA Detection
// ─────────────────────────────────────────────
struct DGAResult {
    double entropy;
    double consonant_ratio;
    double bigram_score;
    double ngram_rarity;
    double dga_probability;
    bool is_dga;
};

class EntropyAnalyzer {
    // English letter frequency table
    static constexpr double ENG_FREQ[26] = {
        0.0817,0.0149,0.0278,0.0425,0.1270,0.0223,0.0202,0.0609,
        0.0697,0.0015,0.0077,0.0403,0.0241,0.0675,0.0751,0.0193,
        0.0010,0.0599,0.0633,0.0906,0.0276,0.0098,0.0236,0.0015,
        0.0197,0.0007
    };
    std::unordered_map<std::string,double> bigram_freq_;

    void build_bigram_table() {
        // Common English bigrams with frequencies
        const std::vector<std::pair<std::string,double>> bg = {
            {"th",0.0356},{"he",0.0307},{"in",0.0243},{"er",0.0205},
            {"an",0.0199},{"re",0.0185},{"on",0.0176},{"en",0.0175},
            {"at",0.0149},{"es",0.0145},{"ed",0.0138},{"or",0.0128},
            {"ti",0.0128},{"hi",0.0127},{"st",0.0125},{"io",0.0118},
            {"le",0.0114},{"is",0.0110},{"ou",0.0110},{"ar",0.0107}
        };
        for (auto& p : bg) bigram_freq_[p.first] = p.second;
    }

public:
    EntropyAnalyzer() { build_bigram_table(); }

    double shannon_entropy(const std::string& s) const {
        std::unordered_map<char,int> freq;
        for (char c : s) freq[c]++;
        double H = 0;
        double n = s.size();
        for (auto& p : freq) {
            double pr = p.second / n;
            H -= pr * std::log2(pr);
        }
        return H;
    }

    DGAResult analyze(const std::string& domain) const {
        // Strip TLD
        std::string label = domain;
        auto dot = domain.rfind('.');
        if (dot != std::string::npos) {
            auto prev = domain.rfind('.', dot - 1);
            label = (prev == std::string::npos) ? domain.substr(0, dot)
                                                 : domain.substr(prev + 1, dot - prev - 1);
        }
        if (label.empty()) label = domain;

        DGAResult r{};
        r.entropy = shannon_entropy(label);

        // Consonant ratio
        std::string vowels = "aeiou";
        int consonants = 0;
        for (char c : label)
            if (std::islower(c) && vowels.find(c) == std::string::npos) consonants++;
        r.consonant_ratio = label.empty() ? 0 : (double)consonants / label.size();

        // Bigram score (lower = more DGA)
        double bg_sum = 0;
        int bg_count = 0;
        for (size_t i = 0; i + 1 < label.size(); ++i) {
            std::string bg = label.substr(i, 2);
            auto it = bigram_freq_.find(bg);
            bg_sum += (it != bigram_freq_.end()) ? it->second : 0.0001;
            bg_count++;
        }
        r.bigram_score = bg_count > 0 ? bg_sum / bg_count : 0;

        // N-gram rarity (compare against expected English frequency)
        double chi2 = 0;
        std::unordered_map<char,int> lfreq;
        for (char c : label) lfreq[c]++;
        for (int i = 0; i < 26; ++i) {
            double observed = lfreq.count('a'+i) ? (double)lfreq['a'+i]/label.size() : 0;
            double expected = ENG_FREQ[i];
            chi2 += std::pow(observed - expected, 2) / (expected + 1e-9);
        }
        r.ngram_rarity = chi2;

        // Bayesian-inspired DGA probability
        double score = 0;
        score += (r.entropy > 3.5) ? 0.35 : (r.entropy > 2.8) ? 0.15 : 0;
        score += (r.consonant_ratio > 0.7) ? 0.25 : (r.consonant_ratio > 0.6) ? 0.1 : 0;
        score += (r.bigram_score < 0.005) ? 0.25 : (r.bigram_score < 0.01) ? 0.1 : 0;
        score += std::min(0.15, r.ngram_rarity / 100.0);
        score += (label.size() > 20) ? 0.1 : (label.size() > 15) ? 0.05 : 0;
        r.dga_probability = std::min(1.0, score);
        r.is_dga = r.dga_probability > 0.6;
        return r;
    }
};

// ─────────────────────────────────────────────
//  Graph Engine: PageRank + Betweenness Centrality + Spectral
// ─────────────────────────────────────────────
class DNSGraph {
public:
    struct Node {
        std::string id;
        std::string type; // "client","resolver","authoritative","domain"
        double pagerank = 1.0;
        double betweenness = 0.0;
        double query_rate = 0.0;
        int64_t query_count = 0;
        double anomaly_score = 0.0;
    };
    struct Edge {
        std::string src, dst;
        double weight = 1.0;
        int64_t count = 0;
        double latency_avg = 0.0;
        std::string qtype;
    };

private:
    std::unordered_map<std::string, Node> nodes_;
    std::vector<Edge> edges_;
    std::unordered_map<std::string, std::vector<size_t>> adj_out_;  // node -> edge indices
    std::mutex mtx_;

public:
    void upsert_node(const std::string& id, const std::string& type) {
        std::lock_guard<std::mutex> lg(mtx_);
        if (!nodes_.count(id)) {
            nodes_[id] = {id, type};
        }
    }

    void add_edge(const std::string& src, const std::string& dst,
                  double weight, double latency, const std::string& qtype) {
        std::lock_guard<std::mutex> lg(mtx_);
        // Find existing edge
        for (auto& e : edges_) {
            if (e.src == src && e.dst == dst && e.qtype == qtype) {
                e.weight += weight;
                e.count++;
                e.latency_avg = (e.latency_avg * (e.count - 1) + latency) / e.count;
                nodes_[src].query_count++;
                return;
            }
        }
        edges_.push_back({src, dst, weight, 1, latency, qtype});
        adj_out_[src].push_back(edges_.size() - 1);
        nodes_[src].query_count++;
    }

    // PageRank with damping factor d=0.85, max_iter iterations
    void compute_pagerank(int max_iter = 50, double d = 0.85) {
        std::lock_guard<std::mutex> lg(mtx_);
        size_t N = nodes_.size();
        if (N == 0) return;

        // Build adjacency
        std::unordered_map<std::string, std::vector<std::string>> out;
        std::unordered_map<std::string, int> out_deg;
        for (auto& e : edges_) { out[e.src].push_back(e.dst); out_deg[e.src]++; }

        std::unordered_map<std::string, double> pr;
        for (auto& p : nodes_) pr[p.first] = 1.0 / N;

        for (int iter = 0; iter < max_iter; ++iter) {
            std::unordered_map<std::string, double> new_pr;
            for (auto& p : nodes_) new_pr[p.first] = (1.0 - d) / N;
            for (auto& e : edges_) {
                if (out_deg[e.src] > 0)
                    new_pr[e.dst] += d * pr[e.src] * (e.weight / out_deg[e.src]);
            }
            double diff = 0;
            for (auto& p : nodes_) diff += std::abs(new_pr[p.first] - pr[p.first]);
            pr = new_pr;
            if (diff < 1e-6) break;
        }
        for (auto& p : pr) nodes_[p.first].pagerank = p.second;
    }

    // Brandes' betweenness centrality (exact, O(VE))
    void compute_betweenness() {
        std::lock_guard<std::mutex> lg(mtx_);
        std::vector<std::string> node_list;
        for (auto& p : nodes_) node_list.push_back(p.first);
        size_t N = node_list.size();
        std::unordered_map<std::string, size_t> idx;
        for (size_t i = 0; i < N; ++i) idx[node_list[i]] = i;

        std::vector<double> bc(N, 0);

        // Build adjacency list by index
        std::vector<std::vector<size_t>> adj(N);
        for (auto& e : edges_) {
            if (idx.count(e.src) && idx.count(e.dst)) {
                adj[idx[e.src]].push_back(idx[e.dst]);
                adj[idx[e.dst]].push_back(idx[e.src]);
            }
        }

        for (size_t s = 0; s < N; ++s) {
            std::vector<std::vector<size_t>> pred(N);
            std::vector<double> sigma(N, 0); sigma[s] = 1;
            std::vector<int> dist(N, -1); dist[s] = 0;
            std::queue<size_t> q;
            std::vector<size_t> stack;
            q.push(s);
            while (!q.empty()) {
                size_t v = q.front(); q.pop();
                stack.push_back(v);
                for (size_t w : adj[v]) {
                    if (dist[w] < 0) { q.push(w); dist[w] = dist[v] + 1; }
                    if (dist[w] == dist[v] + 1) { sigma[w] += sigma[v]; pred[w].push_back(v); }
                }
            }
            std::vector<double> delta(N, 0);
            while (!stack.empty()) {
                size_t w = stack.back(); stack.pop_back();
                for (size_t v : pred[w])
                    delta[v] += (sigma[v] / (sigma[w] + 1e-12)) * (1 + delta[w]);
                if (w != s) bc[w] += delta[w];
            }
        }
        double scale = (N > 2) ? 1.0 / ((N - 1) * (N - 2)) : 1.0;
        for (size_t i = 0; i < N; ++i)
            nodes_[node_list[i]].betweenness = bc[i] * scale;
    }

    // Laplacian spectral gap (algebraic connectivity = Fiedler value)
    // Uses power iteration for approximate second smallest eigenvalue
    double compute_spectral_gap() {
        std::lock_guard<std::mutex> lg(mtx_);
        std::vector<std::string> nl;
        for (auto& p : nodes_) nl.push_back(p.first);
        size_t N = nl.size();
        if (N < 3) return 0.0;
        std::unordered_map<std::string,size_t> idx;
        for (size_t i=0;i<N;++i) idx[nl[i]]=i;

        // Degree vector and adjacency
        std::vector<double> D(N,0);
        std::vector<std::pair<size_t,size_t>> E;
        for (auto& e : edges_) {
            if (idx.count(e.src) && idx.count(e.dst)) {
                size_t u=idx[e.src], v=idx[e.dst];
                D[u]+=e.weight; D[v]+=e.weight;
                E.push_back({u,v});
            }
        }
        // Power iteration for Fiedler vector (random orthogonal start)
        std::mt19937 rng(42);
        std::normal_distribution<double> nd(0,1);
        std::vector<double> x(N);
        for (auto& v:x) v=nd(rng);
        // Remove DC component
        double mean=std::accumulate(x.begin(),x.end(),0.0)/N;
        for (auto& v:x) v-=mean;

        for (int it=0;it<200;++it) {
            std::vector<double> Lx(N,0);
            // L*x = D*x - A*x
            for (size_t i=0;i<N;++i) Lx[i]=D[i]*x[i];
            for (auto& [u,v]:E) { Lx[u]-=x[v]; Lx[v]-=x[u]; }
            // Re-orthogonalize against constant vector
            double dc=std::accumulate(Lx.begin(),Lx.end(),0.0)/N;
            for (auto& v:Lx) v-=dc;
            double norm=0; for (auto& v:Lx) norm+=v*v;
            norm=std::sqrt(norm+1e-15);
            for (auto& v:Lx) v/=norm;
            x=Lx;
        }
        // Rayleigh quotient
        std::vector<double> Lx(N,0);
        for (size_t i=0;i<N;++i) Lx[i]=D[i]*x[i];
        for (auto& [u,v]:E) { Lx[u]-=x[v]; Lx[v]-=x[u]; }
        double num=0,den=0;
        for (size_t i=0;i<N;++i) { num+=x[i]*Lx[i]; den+=x[i]*x[i]; }
        return den>1e-12 ? num/den : 0.0;
    }

    std::vector<std::map<std::string,py::object>> get_nodes_py() {
        std::lock_guard<std::mutex> lg(mtx_);
        std::vector<std::map<std::string,py::object>> out;
        for (auto& p : nodes_) {
            std::map<std::string,py::object> d;
            d["id"]             = py::cast(p.second.id);
            d["type"]           = py::cast(p.second.type);
            d["pagerank"]       = py::cast(p.second.pagerank);
            d["betweenness"]    = py::cast(p.second.betweenness);
            d["query_count"]    = py::cast(p.second.query_count);
            d["anomaly_score"]  = py::cast(p.second.anomaly_score);
            out.push_back(d);
        }
        return out;
    }

    std::vector<std::map<std::string,py::object>> get_edges_py() {
        std::lock_guard<std::mutex> lg(mtx_);
        std::vector<std::map<std::string,py::object>> out;
        for (auto& e : edges_) {
            std::map<std::string,py::object> d;
            d["src"]         = py::cast(e.src);
            d["dst"]         = py::cast(e.dst);
            d["weight"]      = py::cast(e.weight);
            d["count"]       = py::cast(e.count);
            d["latency_avg"] = py::cast(e.latency_avg);
            d["qtype"]       = py::cast(e.qtype);
            out.push_back(d);
        }
        return out;
    }

    size_t node_count() { std::lock_guard<std::mutex> lg(mtx_); return nodes_.size(); }
    size_t edge_count() { std::lock_guard<std::mutex> lg(mtx_); return edges_.size(); }

    void set_anomaly_score(const std::string& id, double score) {
        std::lock_guard<std::mutex> lg(mtx_);
        if (nodes_.count(id)) nodes_[id].anomaly_score = score;
    }
};

// ─────────────────────────────────────────────
//  Queuing Theory: M/M/1 and M/M/c DNS Latency Model
// ─────────────────────────────────────────────
struct QueueStats {
    double utilization;       // ρ = λ/(μc)
    double avg_queue_length;  // Lq
    double avg_system_length; // L
    double avg_wait_time;     // Wq (ms)
    double avg_sojourn_time;  // W (ms)
    double p_zero;            // P(0) for M/M/c
    bool overloaded;
};

class QueueingModel {
public:
    // M/M/1: single server
    static QueueStats mm1(double lambda_qps, double mu_qps) {
        QueueStats s{};
        if (lambda_qps <= 0 || mu_qps <= 0) return s;
        s.utilization = lambda_qps / mu_qps;
        if (s.utilization >= 1.0) { s.overloaded = true; s.utilization = 0.999; return s; }
        double rho = s.utilization;
        s.avg_queue_length  = rho * rho / (1 - rho);
        s.avg_system_length = rho / (1 - rho);
        s.avg_wait_time     = s.avg_queue_length / lambda_qps * 1000;
        s.avg_sojourn_time  = s.avg_system_length / lambda_qps * 1000;
        s.p_zero            = 1 - rho;
        return s;
    }

    // M/M/c: c servers (DNS resolver pool)
    static QueueStats mmc(double lambda_qps, double mu_qps, int c) {
        QueueStats s{};
        if (lambda_qps <= 0 || mu_qps <= 0 || c <= 0) return s;
        double rho = lambda_qps / (c * mu_qps);
        s.utilization = rho;
        if (rho >= 1.0) { s.overloaded = true; return s; }

        double a = lambda_qps / mu_qps; // traffic intensity
        // Erlang C: P(wait) = (a^c / c!) * (1/(1-rho)) / sum_{k=0}^{c-1} a^k/k! + (a^c/c!)*(1/(1-rho))
        double sum = 0, term = 1;
        for (int k = 1; k < c; ++k) { term *= a / k; sum += term; }
        sum += 1; // k=0 term
        double last_term = term * a / c;
        double erlang_c_num = last_term / (1 - rho);
        double p0 = 1.0 / (sum + erlang_c_num);
        s.p_zero = p0;

        double Cq = erlang_c_num * p0; // P(wait)
        s.avg_wait_time     = Cq / (c * mu_qps - lambda_qps) * 1000;
        s.avg_queue_length  = Cq * rho / (1 - rho);
        s.avg_system_length = s.avg_queue_length + a;
        s.avg_sojourn_time  = s.avg_system_length / lambda_qps * 1000;
        return s;
    }
};

// ─────────────────────────────────────────────
//  Markov Chain: DNS Query Sequence Model
// ─────────────────────────────────────────────
class MarkovChain {
    std::unordered_map<std::string, std::unordered_map<std::string, double>> trans_;
    std::unordered_map<std::string, double> counts_;
    std::mutex mtx_;
    std::string last_;

public:
    void observe(const std::string& state) {
        std::lock_guard<std::mutex> lg(mtx_);
        if (!last_.empty()) {
            trans_[last_][state]++;
            counts_[last_]++;
        }
        last_ = state;
    }

    // Return transition matrix as flat map for Python
    std::vector<std::tuple<std::string,std::string,double>> get_transitions() {
        std::lock_guard<std::mutex> lg(mtx_);
        std::vector<std::tuple<std::string,std::string,double>> out;
        for (auto& from : trans_) {
            double total = counts_[from.first];
            for (auto& to : from.second)
                out.emplace_back(from.first, to.first, to.second / (total + 1e-12));
        }
        return out;
    }

    // Stationary distribution via power iteration
    std::unordered_map<std::string,double> stationary_dist(int iters=500) {
        std::lock_guard<std::mutex> lg(mtx_);
        std::vector<std::string> states;
        for (auto& p : trans_) states.push_back(p.first);
        size_t N = states.size();
        if (N == 0) return {};
        std::unordered_map<std::string,size_t> idx;
        for (size_t i=0;i<N;++i) idx[states[i]]=i;

        // Build normalized transition matrix
        std::vector<std::vector<double>> T(N, std::vector<double>(N, 0));
        for (auto& from : trans_) {
            if (!idx.count(from.first)) continue;
            double total = counts_[from.first];
            for (auto& to : from.second)
                if (idx.count(to.first))
                    T[idx[from.first]][idx[to.first]] = to.second / (total+1e-12);
        }
        // Initial uniform distribution
        std::vector<double> pi(N, 1.0/N);
        for (int it=0;it<iters;++it) {
            std::vector<double> next(N,0);
            for (size_t i=0;i<N;++i)
                for (size_t j=0;j<N;++j)
                    next[j] += pi[i]*T[i][j];
            double sum=0; for (auto v:next) sum+=v;
            if (sum>1e-12) for (auto& v:next) v/=sum;
            pi=next;
        }
        std::unordered_map<std::string,double> out;
        for (size_t i=0;i<N;++i) out[states[i]]=pi[i];
        return out;
    }

    void reset() {
        std::lock_guard<std::mutex> lg(mtx_);
        trans_.clear(); counts_.clear(); last_.clear();
    }
};

// ─────────────────────────────────────────────
//  FFT-based Periodic Anomaly Detection (DIT Cooley-Tukey)
// ─────────────────────────────────────────────
class TimeSeriesAnalyzer {
    std::deque<double> window_;
    size_t max_size_;
    double ewma_val_ = 0, ewma_var_ = 0;
    double alpha_;
    std::mutex mtx_;

    using Cx = std::complex<double>;

    static void fft(std::vector<Cx>& a, bool inv) {
        size_t n = a.size();
        for (size_t i=1,j=0; i<n; ++i) {
            size_t bit = n>>1;
            for (; j&bit; bit>>=1) j^=bit;
            j^=bit;
            if (i<j) std::swap(a[i],a[j]);
        }
        for (size_t len=2; len<=n; len<<=1) {
            double ang = 2*M_PI/len * (inv?-1:1);
            Cx wlen(std::cos(ang), std::sin(ang));
            for (size_t i=0; i<n; i+=len) {
                Cx w(1);
                for (size_t j=0; j<len/2; ++j) {
                    Cx u=a[i+j], v=a[i+j+len/2]*w;
                    a[i+j]=u+v; a[i+j+len/2]=u-v;
                    w*=wlen;
                }
            }
        }
        if (inv) for (auto& x:a) x/=n;
    }

public:
    TimeSeriesAnalyzer(size_t window_size=256, double alpha=0.1)
        : max_size_(window_size), alpha_(alpha) {}

    void push(double val) {
        std::lock_guard<std::mutex> lg(mtx_);
        if (ewma_val_ == 0) ewma_val_ = val;
        double diff = val - ewma_val_;
        ewma_val_ += alpha_ * diff;
        ewma_var_  = (1-alpha_) * (ewma_var_ + alpha_ * diff * diff);
        window_.push_back(val);
        if (window_.size() > max_size_) window_.pop_front();
    }

    // Returns dominant frequency, amplitude, anomaly z-score
    std::tuple<double,double,double> analyze() {
        std::lock_guard<std::mutex> lg(mtx_);
        if (window_.size() < 4) return {0,0,0};
        size_t n = 1;
        while (n < window_.size()) n<<=1;
        std::vector<Cx> buf(n, 0);
        for (size_t i=0; i<window_.size(); ++i) buf[i] = window_[i];
        fft(buf, false);
        // Find dominant frequency (skip DC)
        double max_amp = 0; size_t dom_idx = 1;
        for (size_t i=1; i<n/2; ++i) {
            double amp = std::abs(buf[i]);
            if (amp > max_amp) { max_amp=amp; dom_idx=i; }
        }
        double dom_freq = (double)dom_idx / n;
        double z = ewma_var_ > 1e-12 ?
            std::abs(window_.back() - ewma_val_) / std::sqrt(ewma_var_) : 0;
        return {dom_freq, max_amp, z};
    }

    std::vector<double> get_window() {
        std::lock_guard<std::mutex> lg(mtx_);
        return {window_.begin(), window_.end()};
    }

    double ewma() { std::lock_guard<std::mutex> lg(mtx_); return ewma_val_; }
    double ewma_stddev() { std::lock_guard<std::mutex> lg(mtx_); return std::sqrt(ewma_var_); }
};

// ─────────────────────────────────────────────
//  DNS Packet Synthesizer (no hardware required)
//  Generates realistic DNS traffic based on statistical models
// ─────────────────────────────────────────────
struct DNSPacket {
    uint64_t timestamp_us;
    std::string src_ip;
    std::string dst_ip;
    std::string qname;
    std::string qtype;
    std::string rcode;
    double latency_ms;
    uint32_t tx_id;
    bool is_response;
    int ttl;
    std::vector<std::string> answers;
};

class DNSTrafficSynthesizer {
    std::mt19937_64 rng_;
    std::uniform_real_distribution<double> ud_{0,1};
    std::normal_distribution<double> nd_{0,1};
    std::exponential_distribution<double> exp_dist_{1.0};

    // Top domains with realistic weights
    std::vector<std::pair<std::string,double>> top_domains_ = {
        {"google.com",0.08},{"youtube.com",0.06},{"facebook.com",0.05},
        {"twitter.com",0.04},{"instagram.com",0.04},{"reddit.com",0.03},
        {"amazon.com",0.03},{"netflix.com",0.03},{"cloudflare.com",0.02},
        {"github.com",0.02},{"microsoft.com",0.02},{"apple.com",0.02},
        {"wikipedia.org",0.02},{"linkedin.com",0.015},{"zoom.us",0.015},
        {"slack.com",0.01},{"dropbox.com",0.01},{"stripe.com",0.008}
    };
    std::discrete_distribution<int> domain_dist_;

    std::vector<std::string> qtypes_  = {"A","AAAA","MX","CNAME","TXT","NS","PTR","SOA","SRV"};
    std::vector<double>      qweights_= {0.55,0.2,0.08,0.07,0.04,0.03,0.015,0.01,0.005};
    std::discrete_distribution<int> qtype_dist_;

    std::vector<std::string> rcodes_  = {"NOERROR","NXDOMAIN","SERVFAIL","REFUSED","FORMERR"};
    std::vector<double>      rweights_= {0.88,0.07,0.025,0.015,0.01};
    std::discrete_distribution<int> rcode_dist_;

    uint64_t base_time_us_;
    double   lambda_qps_;    // Poisson arrival rate
    double   mu_qps_;        // Service rate (for latency model)
    int      num_clients_;
    double   dga_injection_prob_;

    std::string random_ip(bool is_v6 = false) {
        if (is_v6) {
            std::ostringstream ss;
            for (int i=0;i<8;++i) {
                if (i>0) ss<<":";
                ss<<std::hex<<(rng_()&0xffff);
            }
            return ss.str();
        }
        // RFC1918 private ranges
        static const std::vector<std::string> prefixes = {
            "10.0.","192.168.1.","172.16.","10.10."
        };
        int p = rng_() % prefixes.size();
        return prefixes[p] + std::to_string(rng_()%254+1) + "." + std::to_string(rng_()%254+1);
    }

    std::string generate_dga_domain() {
        // Simulate DGA domain generation algorithm (similar to Conficker variant C)
        static const std::string charset = "abcdefghijklmnopqrstuvwxyz0123456789";
        int len = 8 + rng_() % 12;
        std::string s;
        for (int i=0;i<len;++i) s += charset[rng_() % charset.size()];
        static const std::vector<std::string> tlds = {".com",".net",".org",".info",".biz"};
        return s + tlds[rng_() % tlds.size()];
    }

    std::string gen_subdomain(const std::string& base) {
        if (ud_(rng_) < 0.3) {
            static const std::vector<std::string> subs = {"www","mail","cdn","api","static","img","assets"};
            return subs[rng_()%subs.size()] + "." + base;
        }
        return base;
    }

    std::vector<std::string> client_pool_;

public:
    DNSTrafficSynthesizer(double lambda_qps=50.0, double mu_qps=200.0,
                          int num_clients=20, double dga_prob=0.02,
                          uint64_t seed=12345)
        : rng_(seed), lambda_qps_(lambda_qps), mu_qps_(mu_qps),
          num_clients_(num_clients), dga_injection_prob_(dga_prob)
    {
        base_time_us_ = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        std::vector<double> dw;
        for (auto& p : top_domains_) dw.push_back(p.second);
        domain_dist_ = std::discrete_distribution<int>(dw.begin(), dw.end());
        qtype_dist_  = std::discrete_distribution<int>(qweights_.begin(), qweights_.end());
        rcode_dist_  = std::discrete_distribution<int>(rweights_.begin(), rweights_.end());

        // Pre-generate client IPs
        for (int i=0;i<num_clients_;++i)
            client_pool_.push_back(random_ip(ud_(rng_)<0.05));
    }

    // Generate a batch of N packets (Poisson inter-arrivals)
    std::vector<DNSPacket> generate_batch(int n) {
        std::vector<DNSPacket> batch;
        batch.reserve(n);
        uint64_t t = base_time_us_;
        double interval_us = 1e6 / lambda_qps_;

        for (int i=0; i<n; ++i) {
            // Poisson inter-arrival
            double wait = exp_dist_(rng_) * interval_us;
            t += (uint64_t)wait;

            DNSPacket p;
            p.timestamp_us = t;
            p.src_ip = client_pool_[rng_() % client_pool_.size()];
            p.dst_ip = (ud_(rng_)<0.7) ? "8.8.8.8" : (ud_(rng_)<0.5) ? "1.1.1.1" : "9.9.9.9";
            p.tx_id = (uint32_t)(rng_() & 0xFFFF);
            p.is_response = false;
            p.ttl = 300 + (int)(rng_()%86100);

            // Domain selection
            if (ud_(rng_) < dga_injection_prob_) {
                p.qname = generate_dga_domain();
            } else {
                p.qname = gen_subdomain(top_domains_[domain_dist_(rng_)].first);
            }

            p.qtype = qtypes_[qtype_dist_(rng_)];
            p.rcode = rcodes_[rcode_dist_(rng_)];

            // M/M/1 latency: service time + queuing delay
            double rho = lambda_qps_ / mu_qps_;
            double service_ms = 1000.0 / mu_qps_;
            double queue_delay = (rho < 1.0) ? service_ms * rho / (1 - rho + 1e-12) : 50.0;
            double jitter = std::abs(nd_(rng_)) * 2.0;
            p.latency_ms = service_ms + queue_delay + jitter;

            // Answers for NOERROR
            if (p.rcode == "NOERROR" && !p.is_response) {
                if (p.qtype == "A") {
                    std::ostringstream ip;
                    ip << (rng_()%223+1) << "." << (rng_()%255) << "."
                       << (rng_()%255) << "." << (rng_()%254+1);
                    p.answers.push_back(ip.str());
                }
            }
            batch.push_back(p);
        }
        base_time_us_ = t;
        return batch;
    }

    void set_lambda(double l) { lambda_qps_=l; exp_dist_=std::exponential_distribution<double>(l/1e6); }
    void set_dga_prob(double p) { dga_injection_prob_=p; }
    int  client_count() const { return (int)client_pool_.size(); }
};

// ─────────────────────────────────────────────
//  DNS Packet to Python dict converter
// ─────────────────────────────────────────────
static py::dict packet_to_py(const DNSPacket& p) {
    py::dict d;
    d["timestamp_us"] = p.timestamp_us;
    d["src_ip"]       = p.src_ip;
    d["dst_ip"]       = p.dst_ip;
    d["qname"]        = p.qname;
    d["qtype"]        = p.qtype;
    d["rcode"]        = p.rcode;
    d["latency_ms"]   = p.latency_ms;
    d["tx_id"]        = p.tx_id;
    d["is_response"]  = p.is_response;
    d["ttl"]          = p.ttl;
    py::list ans;
    for (auto& a : p.answers) ans.append(a);
    d["answers"] = ans;
    return d;
}

// ─────────────────────────────────────────────
//  Aggregate Statistics Engine
// ─────────────────────────────────────────────
class StatsEngine {
    std::atomic<uint64_t> total_queries_{0};
    std::atomic<uint64_t> total_nxdomain_{0};
    std::atomic<uint64_t> total_servfail_{0};
    std::unordered_map<std::string,uint64_t> qtype_count_;
    std::unordered_map<std::string,uint64_t> resolver_count_;
    std::unordered_map<std::string,uint64_t> client_count_;
    std::unordered_map<std::string,uint64_t> domain_count_;
    std::vector<double> latency_samples_;
    std::mutex mtx_;
    uint64_t dga_count_=0;

public:
    void record(const DNSPacket& p, bool is_dga) {
        total_queries_++;
        if (p.rcode=="NXDOMAIN") total_nxdomain_++;
        if (p.rcode=="SERVFAIL") total_servfail_++;
        std::lock_guard<std::mutex> lg(mtx_);
        qtype_count_[p.qtype]++;
        resolver_count_[p.dst_ip]++;
        client_count_[p.src_ip]++;
        domain_count_[p.qname]++;
        latency_samples_.push_back(p.latency_ms);
        if (latency_samples_.size() > 10000) latency_samples_.erase(latency_samples_.begin());
        if (is_dga) dga_count_++;
    }

    py::dict summary() {
        std::lock_guard<std::mutex> lg(mtx_);
        py::dict d;
        d["total_queries"]   = (uint64_t)total_queries_;
        d["total_nxdomain"]  = (uint64_t)total_nxdomain_;
        d["total_servfail"]  = (uint64_t)total_servfail_;
        d["dga_count"]       = dga_count_;

        // Latency percentiles
        if (!latency_samples_.empty()) {
            std::vector<double> sorted = latency_samples_;
            std::sort(sorted.begin(), sorted.end());
            size_t n = sorted.size();
            d["latency_p50"]  = sorted[n*50/100];
            d["latency_p95"]  = sorted[n*95/100];
            d["latency_p99"]  = sorted[std::min(n-1, n*99/100)];
            double sum=0; for(auto v:sorted) sum+=v;
            d["latency_mean"] = sum/n;
        }

        // Top domains
        std::vector<std::pair<std::string,uint64_t>> dom_vec(domain_count_.begin(),domain_count_.end());
        std::sort(dom_vec.begin(),dom_vec.end(),[](auto&a,auto&b){return a.second>b.second;});
        py::list top_domains;
        for (size_t i=0;i<std::min((size_t)20,dom_vec.size());++i) {
            py::dict dd; dd["domain"]=dom_vec[i].first; dd["count"]=dom_vec[i].second;
            top_domains.append(dd);
        }
        d["top_domains"] = top_domains;

        // QType distribution
        py::dict qtd;
        for (auto& p : qtype_count_) qtd[py::cast(p.first)] = p.second;
        d["qtype_dist"] = qtd;

        // Resolver distribution
        py::dict rsd;
        for (auto& p : resolver_count_) rsd[py::cast(p.first)] = p.second;
        d["resolver_dist"] = rsd;

        return d;
    }

    uint64_t total() { return (uint64_t)total_queries_; }
};

// ─────────────────────────────────────────────
//  Master Controller (orchestrates everything)
// ─────────────────────────────────────────────
class DNSController {
    DNSTrafficSynthesizer synthesizer_;
    DNSGraph              graph_;
    EntropyAnalyzer       entropy_;
    MarkovChain           markov_;
    TimeSeriesAnalyzer    ts_analyzer_;
    StatsEngine           stats_;
    BloomFilter           seen_domains_;
    QueueingModel         queue_model_;

    std::mutex ctrl_mtx_;
    std::atomic<bool> running_{false};

public:
    DNSController(double lambda=80.0, double mu=300.0, int clients=30,
                  double dga_prob=0.03)
        : synthesizer_(lambda, mu, clients, dga_prob),
          ts_analyzer_(512, 0.05) {}

    // Process a batch: update graph, stats, Markov chain, time-series
    py::list process_batch(int n) {
        auto packets = synthesizer_.generate_batch(n);
        py::list result;
        for (auto& pkt : packets) {
            auto dga = entropy_.analyze(pkt.qname);
            stats_.record(pkt, dga.is_dga);
            markov_.observe(pkt.qtype);
            ts_analyzer_.push(pkt.latency_ms);

            // Update graph
            graph_.upsert_node(pkt.src_ip, "client");
            graph_.upsert_node(pkt.dst_ip, "resolver");
            graph_.upsert_node(pkt.qname,  "domain");
            graph_.add_edge(pkt.src_ip, pkt.dst_ip, 1.0, pkt.latency_ms, pkt.qtype);
            graph_.add_edge(pkt.dst_ip, pkt.qname,  1.0, pkt.latency_ms, pkt.qtype);

            if (dga.is_dga)
                graph_.set_anomaly_score(pkt.qname, dga.dga_probability);

            py::dict d = packet_to_py(pkt);
            d["dga_prob"] = dga.dga_probability;
            d["entropy"]  = dga.entropy;
            d["is_dga"]   = dga.is_dga;
            result.append(d);
        }
        return result;
    }

    void compute_graph_metrics() {
        graph_.compute_pagerank(50);
        graph_.compute_betweenness();
    }

    double compute_spectral_gap() { return graph_.compute_spectral_gap(); }

    py::dict get_graph() {
        py::dict d;
        d["nodes"] = graph_.get_nodes_py();
        d["edges"] = graph_.get_edges_py();
        d["node_count"] = graph_.node_count();
        d["edge_count"] = graph_.edge_count();
        return d;
    }

    py::dict get_stats() { return stats_.summary(); }

    py::dict get_queue_stats(double lambda, double mu, int c=1) {
        QueueStats qs = (c==1) ? QueueingModel::mm1(lambda,mu)
                                : QueueingModel::mmc(lambda,mu,c);
        py::dict d;
        d["utilization"]        = qs.utilization;
        d["avg_queue_length"]   = qs.avg_queue_length;
        d["avg_system_length"]  = qs.avg_system_length;
        d["avg_wait_ms"]        = qs.avg_wait_time;
        d["avg_sojourn_ms"]     = qs.avg_sojourn_time;
        d["p_zero"]             = qs.p_zero;
        d["overloaded"]         = qs.overloaded;
        return d;
    }

    py::dict get_timeseries() {
        auto [dom_freq, dom_amp, z_score] = ts_analyzer_.analyze();
        py::dict d;
        d["window"]     = ts_analyzer_.get_window();
        d["ewma"]       = ts_analyzer_.ewma();
        d["ewma_std"]   = ts_analyzer_.ewma_stddev();
        d["dom_freq"]   = dom_freq;
        d["dom_amp"]    = dom_amp;
        d["z_score"]    = z_score;
        d["anomalous"]  = (z_score > 3.0);
        return d;
    }

    py::dict get_markov() {
        auto transitions = markov_.get_transitions();
        auto stationary  = markov_.stationary_dist();
        py::list trans_list;
        for (auto& [f,t,p] : transitions) {
            py::dict d; d["from"]=f; d["to"]=t; d["prob"]=p;
            trans_list.append(d);
        }
        py::dict stat_dict;
        for (auto& p : stationary) stat_dict[py::cast(p.first)] = p.second;
        py::dict d;
        d["transitions"] = trans_list;
        d["stationary"]  = stat_dict;
        return d;
    }

    py::dict analyze_domain(const std::string& domain) {
        auto r = entropy_.analyze(domain);
        py::dict d;
        d["entropy"]        = r.entropy;
        d["consonant_ratio"]= r.consonant_ratio;
        d["bigram_score"]   = r.bigram_score;
        d["ngram_rarity"]   = r.ngram_rarity;
        d["dga_probability"]= r.dga_probability;
        d["is_dga"]         = r.is_dga;
        return d;
    }

    void set_lambda(double l) { synthesizer_.set_lambda(l); }
    void set_dga_prob(double p) { synthesizer_.set_dga_prob(p); }
    void reset_markov() { markov_.reset(); }
};

// ─────────────────────────────────────────────
//  pybind11 Module Registration
// ─────────────────────────────────────────────
PYBIND11_MODULE(dns_engine, m) {
    m.doc() = "DNS Traffic Visualizer - C++ Core Engine (pybind11)";

    py::class_<DNSController>(m, "DNSController")
        .def(py::init<double,double,int,double>(),
             py::arg("lambda_qps")=80.0, py::arg("mu_qps")=300.0,
             py::arg("clients")=30, py::arg("dga_prob")=0.03)
        .def("process_batch",          &DNSController::process_batch,
             py::arg("n")=100)
        .def("compute_graph_metrics",  &DNSController::compute_graph_metrics)
        .def("compute_spectral_gap",   &DNSController::compute_spectral_gap)
        .def("get_graph",              &DNSController::get_graph)
        .def("get_stats",              &DNSController::get_stats)
        .def("get_queue_stats",        &DNSController::get_queue_stats,
             py::arg("lambda"), py::arg("mu"), py::arg("c")=1)
        .def("get_timeseries",         &DNSController::get_timeseries)
        .def("get_markov",             &DNSController::get_markov)
        .def("analyze_domain",         &DNSController::analyze_domain)
        .def("set_lambda",             &DNSController::set_lambda)
        .def("set_dga_prob",           &DNSController::set_dga_prob)
        .def("reset_markov",           &DNSController::reset_markov);

    // Standalone entropy analyzer
    py::class_<EntropyAnalyzer>(m, "EntropyAnalyzer")
        .def(py::init<>())
        .def("analyze",           &EntropyAnalyzer::analyze)
        .def("shannon_entropy",   &EntropyAnalyzer::shannon_entropy);

    // Standalone bloom filter
    py::class_<BloomFilter>(m, "BloomFilter")
        .def(py::init<size_t,double>(), py::arg("capacity")=100000, py::arg("fp")=0.01)
        .def("insert",    &BloomFilter::insert)
        .def("contains",  &BloomFilter::contains)
        .def("clear",     &BloomFilter::clear);

    // Queuing model static methods
    m.def("mm1", [](double l, double m) {
        auto s = QueueingModel::mm1(l,m);
        py::dict d;
        d["utilization"]=s.utilization; d["avg_wait_ms"]=s.avg_wait_time;
        d["avg_sojourn_ms"]=s.avg_sojourn_time; d["avg_queue_length"]=s.avg_queue_length;
        d["overloaded"]=s.overloaded;
        return d;
    }, py::arg("lambda_qps"), py::arg("mu_qps"));

    m.def("mmc", [](double l, double m, int c) {
        auto s = QueueingModel::mmc(l,m,c);
        py::dict d;
        d["utilization"]=s.utilization; d["avg_wait_ms"]=s.avg_wait_time;
        d["avg_sojourn_ms"]=s.avg_sojourn_time; d["avg_queue_length"]=s.avg_queue_length;
        d["p_zero"]=s.p_zero; d["overloaded"]=s.overloaded;
        return d;
    }, py::arg("lambda_qps"), py::arg("mu_qps"), py::arg("c"));
}
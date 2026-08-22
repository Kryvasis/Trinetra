#include "probes/scanner.hpp"
#include "probes/tcp_probe.hpp"
#include "probes/udp_probe.hpp"
#include "probes/icmp_probe.hpp"
#include "utils/time_utils.hpp"
#include <atomic>
#include <mutex>
#include <thread>
#include <vector>
#include <queue>
#include <condition_variable>

namespace iskabon::probes {

Scanner::Scanner(int workers, double timeout_sec)
    : workers_(workers), timeout_sec_(timeout_sec) {}

ScanStats Scanner::run(
    const std::vector<planner::ProbeJob>& jobs,
    const ResultCallback&                 on_result)
{
    ScanStats stats;
    stats.total = static_cast<int>(jobs.size());
    if (jobs.empty()) return stats;

    double t0 = utils::monotonic_ms();

    // Work queue
    std::mutex              qmtx;
    std::condition_variable qcv;
    std::queue<const planner::ProbeJob*> work_q;
    bool done = false;

    for (const auto& j : jobs) work_q.push(&j);

    std::atomic<int> open_a{0}, closed_a{0}, err_a{0};

    std::mutex cbmtx;
    auto safe_cb = [&](const ProbeResult& r) {
        std::lock_guard<std::mutex> lk(cbmtx);
        on_result(r);
    };

    auto worker_fn = [&]() {
        TcpProbe  tcp_probe(timeout_sec_);
        UdpProbe  udp_probe(timeout_sec_);
        IcmpProbe icmp_probe(timeout_sec_);

        while (true) {
            const planner::ProbeJob* job = nullptr;
            {
                std::unique_lock<std::mutex> lk(qmtx);
                qcv.wait(lk, [&]{ return !work_q.empty() || done; });
                if (work_q.empty()) return;
                job = work_q.front();
                work_q.pop();
            }
            qcv.notify_one();

            ProbeResult r;
            switch (job->protocol) {
                case Protocol::TCP:  r = tcp_probe.run(job->host, job->port);  break;
                case Protocol::UDP:  r = udp_probe.run(job->host, job->port);  break;
                case Protocol::ICMP: r = icmp_probe.run(job->host, 0);         break;
                default:             r = { job->host, job->protocol, job->port,
                                           "unsupported", std::nullopt, "protocol not implemented" };
            }

            if (r.status.find("open") != std::string::npos || r.status.find("up") != std::string::npos)
                open_a++;
            else if (r.status == "closed" || r.status == "down" || r.status == "unknown")
                closed_a++;
            else
                err_a++;

            safe_cb(r);
        }
    };

    int nw = std::min(workers_, static_cast<int>(jobs.size()));
    std::vector<std::thread> threads;
    threads.reserve(nw);
    for (int i = 0; i < nw; ++i) {
        qcv.notify_all();
        threads.emplace_back(worker_fn);
    }
    qcv.notify_all();

    {
        std::lock_guard<std::mutex> lk(qmtx);
        done = true;
    }
    qcv.notify_all();

    for (auto& t : threads) t.join();

    stats.open_count = open_a.load();
    stats.closed     = closed_a.load();
    stats.errors     = err_a.load();
    stats.elapsed_s  = (utils::monotonic_ms() - t0) / 1000.0;
    return stats;
}

} // namespace iskabon::probes

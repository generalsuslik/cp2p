//
// Created by General Suslik on 17.08.2025.
//

#include "graph.hpp"

#include <spdlog/spdlog.h>

namespace cp2p {

    void Graph::route_message(const PeerId& sender, const GraphMessage& message) {
        if (!seen_messages_.insert(message.id).second) {
            return;
        }

        if (message.receiver == sender) {
            return;
        }

        for (auto& [peer_id, conns] : connections_) {
            if (peer_id == sender) {
                continue;
            }
            for (auto& conn : conns) {
                conn->deliver(*message.message);
            }
        }
    }

    void Graph::send_directly(const PeerId& receiver, const MessagePtr& message) {
        auto it = connections_.find(receiver);
        if (it == connections_.end()) {
            spdlog::error("[Graph::send_directly] id: {} not found", receiver);
            return;
        }


    }

    void Graph::add_connection(const Node::ID& id, const std::shared_ptr<Connection>& conn) {
        connections_[id].insert(conn);
    }

    void Graph::remove_connection(const Node::ID& id, const std::shared_ptr<Connection>& conn) {
        auto it = connections_.find(id);
        if (it == connections_.end()) {
            spdlog::error("[Graph::remove_connection] id: {} not found", id);
            return;
        }

        it->second.erase(conn);
        if (it->second.empty()) {
            connections_.erase(it);
        }
    }

    std::shared_ptr<Connection> Graph::get_connection(const Node::ID& target_id) const {
        auto it = connections_.find(target_id);
        if (it != connections_.end()) {
            return *it->second.begin();
        }
        return nullptr;
    }

    const std::unordered_map<Graph::PeerId, Graph::Connections>& Graph::get_neighbours() const {
        return connections_;
    }

} // namespace cp2p

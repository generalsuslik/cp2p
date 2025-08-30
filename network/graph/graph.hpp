//
// Created by General Suslik on 17.08.2025.
//

#ifndef CP2P_GRAPH_HPP
#define CP2P_GRAPH_HPP

#include "unordered_map"
#include "unordered_set"

#include "network/core/connection.hpp"
#include "network/core/message.hpp"
#include "network/node.hpp"

namespace cp2p {

    /**
     * @brief graph represents connection between nodes (peers)
     */
    class Graph {
    public:
        using Connections = std::unordered_set<std::shared_ptr<Connection>, ConnPtrHash, ConnPtrEqual>;
        using PeerId = Node::ID;
        using MessageId = std::string;

    private:
        struct GraphMessage {
            MessageId id;
            PeerId sender;
            PeerId receiver;
            MessagePtr message;
        };

    public:
        Graph() = default;

        void route_message(const PeerId& sender, const GraphMessage& message);

        void send_directly(const PeerId& receiver, const MessagePtr& message);

        void add_connection(const Node::ID& id, const std::shared_ptr<Connection>& conn);

        void remove_connection(const Node::ID& id, const std::shared_ptr<Connection>& conn);

        std::shared_ptr<Connection> get_connection(const Node::ID& target_id) const;

        const std::unordered_map<PeerId, Connections>& get_neighbours() const;

    private:
        std::unordered_map<PeerId, Connections> connections_;

        mutable std::unordered_set<MessageId> seen_messages_;
    };

} // namespace cp2p

#endif //CP2P_GRAPH_HPP
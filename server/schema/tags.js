const { gql } = require("apollo-server");
const fetchCbrain = require("../cbrain-api");
const {
  paginateResults,
  sortResults,
  snakeKey,
  camelKey
} = require("../utils");

const route = "tags";

const typeDefs = gql`
  extend type Query {
    getTagById(id: ID!): Tag
    getTags(
      cursor: String
      limit: Int
      sortBy: GroupSort
      orderBy: Order
    ): TagFeed!
  }

  extend type Mutation {
    createTag(input: TagInput): Tag
    deleteTag(id: ID!): Response
    updateTag(id: ID!, input: TagInput): Tag
  }

  input TagInput {
    id: ID
    name: String
    userId: ID
    groupId: ID
  }

  type Tag {
    id: ID
    name: String
    userId: ID
    groupId: ID
  }

  type TagFeed {
    cursor: String!
    hasMore: Boolean!
    tags: [Tag]!
  }

  enum TagSort {
    id
    name
    userId
    groupId
  }
`;

const resolvers = {
  Query: {
    getTags: async (_, { cursor, limit, sortBy, orderBy }, context) => {
      const results = await fetchCbrain(context, route)
        .then(data => data.json())
        .then(tags => tags.map(tag => camelKey(tag)));
      return paginateResults({
        cursor,
        limit,
        results: sortResults({ sortBy, orderBy, results }),
        route
      });
    },
    getTagById: (_, { id }, context) => {
      return fetchCbrain(context, `${route}/${id}`)
        .then(data => data.json())
        .then(tag => camelKey(tag));
    }
  },
  Mutation: {
    createTag: (_, { input }, context) => {
      return fetchCbrain(
        context,
        `${route}`,
        { method: "POST" },
        { tag: snakeKey(input) }
      )
        .then(data => data.json())
        .then(tag => camelKey(tag));
    },
    updateTag: (_, { id, input }, context) => {
      const tag = {
        ...input,
        user_id: input.userId,
        group_id: input.groupId
      };
      return fetchCbrain(context, `${route}/${id}`, { method: "PUT" }, { tag })
        .then(data => data.json())
        .then(tag => camelKey(tag));
    },
    deleteTag: (_, { id }, context) => {
      return fetchCbrain(context, `${route}/${id}`, { method: "DELETE" }).then(
        res => {
          return {
            status: res.status,
            success: res.status === 200
          };
        }
      );
    }
  }
};

module.exports = { typeDefs, resolvers };

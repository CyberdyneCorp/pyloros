## Decisions

Apply the classification when translating worker failures into a v1 history row. Keep the reported diagnostic and preserve guest success output even if it mentions a timeout. Worker deadlines continue to produce timeout history directly.

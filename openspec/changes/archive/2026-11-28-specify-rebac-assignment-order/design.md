## Write and read visibility

Both writers acquire the client registration lock and validate their change against the committed graph. A grant validates the subject type against the current model. A replacement checks existing user and object assignments before storing its model. Permission readers continue to see committed data throughout the overlap.

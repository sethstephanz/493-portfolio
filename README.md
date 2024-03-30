Portfolio Project for CS 493: Cloud Application Development

In this cloud-based database management project, multiple entities were modelled: Ships, loads, and ship owners.
The goal was to manage entities that relate to each other in different ways. Ships can carry multiple loads, and each load contains
a record of the ship on which it is carried. Meanwhile, ships are owned by one and only one owner at a time. Both the ship owner
and ship entities contain records of their respective relative entity. Byproducts of standard database operations are accounted for.
For instance, a ship that is carrying cargo can be deleted. The cargo is not deleted along with the ship, but its 'carrier' property is set to Null.

This project uses Auth0 to secure several API endpoints and was originally deployed to Google Cloud.

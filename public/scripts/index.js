const showBtn = document.querySelectorAll("#show-btn"),
  closeBtn = document.querySelectorAll("#close-btn");
//Simple script to toggle show password button
const toggleBtn = () => {
  showBtn.forEach((item, index) => {
    item.addEventListener("click", () => {
      closeBtn[index].classList.toggle("toggleDisplay");
    });
  });
};
toggleBtn();
